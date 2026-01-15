import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import feedparser
import requests
import re
import pandas as pd
import time
from datetime import datetime, timedelta
import save_functions
import smtplib
from email.mime.text import MIMEText
from email.header import Header
import os  

# ================== CONFIGURATION DU DESIGN ==================

COULEURS = {
    "bg_app": "#f4f6f9",        # Gris très clair
    "bg_panel": "#ffffff",      # Blanc
    "primary": "#2c3e50",       # Bleu nuit
    "primary_hover": "#34495e", 
    "accent": "#e74c3c",        # Rouge
    "text": "#2c3e50",
    "log_bg": "#1e1e1e",        # Noir (Console)
    "log_text": "#d4d4d4",      # Blanc gris (Console)
    "log_info": "#61afef",      # Bleu (Console)
    "log_warn": "#e5c07b",      # Jaune (Console)
    "log_err": "#e06c75"        # Rouge (Console)
}

POLICE_TITRE = ("Segoe UI", 12, "bold")
POLICE_TEXTE = ("Segoe UI", 10)
POLICE_BOUTON = ("Segoe UI", 10, "bold")

# ================== VARIABLES GLOBALES ==================

CONFIG = {
    "BREVO_SMTP_LOGIN": "9fb516001@smtp-brevo.com",
    "BREVO_API_KEY": "", 
    "BREVO_SENDER_EMAIL": "projet.alertes.esilv@gmail.com",
    "ALERT_MAILING_LIST": [], 
    "MODE_LOCAL": False,
    "SMTP_SERVER": "smtp-relay.brevo.com",
    "SMTP_PORT": 587
}

# URLs fixes
RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
CVE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"

# Fichier historique
HISTORY_FILE = "alert_history.json"

# ================== FONCTIONS LOGIQUES ==================

def print_step(titre):
    print("\n" + "-"*60)
    print(f"ETAPE : {titre}")
    print("-"*60)

def recupFlux():
    print_step("Recuperation des flux RSS ANSSI")
    headers = {"User-Agent": "Mozilla/5.0 (ESILV Student Project)"}

    def charger(url, label, fichier_cache):
        if CONFIG["MODE_LOCAL"]:
            print(f"[INFO] Mode LOCAL : Chargement cache {label}...")
            return save_functions.charger_json_en_dict(fichier_cache) or {}

        flux_cache = save_functions.charger_json_en_dict(fichier_cache) or {}
        try:
            print(f"[INFO] Telechargement {label}...")
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            rss = feedparser.parse(resp.text)
            nb = len(rss.entries)
            print(f"[INFO] {nb} entrees trouvees dans {label}")

            maj = False
            for e in rss.entries:
                if e.title not in flux_cache:
                    flux_cache[e.title] = {
                        "description": e.description, "link": e.link,
                        "published": e.published, "json_content": None
                    }
                    maj = True
                else:
                    if flux_cache[e.title].get("published") != e.published:
                        flux_cache[e.title].update({
                            "description": e.description, "link": e.link,
                            "published": e.published, "json_content": None
                        })
                        maj = True
            
            if maj:
                save_functions.sauvegarder_dict_en_json(flux_cache, fichier_cache)
            return flux_cache
        except Exception as e:
            print(f"[ERREUR] Chargement {label} : {e}")
            return flux_cache

    rss_alertes = charger(RSS_ALERTES, "Alertes ANSSI", "flux_alerte.json")
    rss_avis = charger(RSS_AVIS, "Avis ANSSI", "flux_avis.json")
    return rss_alertes, rss_avis

def extraire_cves_depuis_flux(flux, nom_flux):
    print_step(f"Extraction des CVE : {nom_flux}")
    resultat = {}
    total_cve = 0
    total_bulletins = len(flux)
    compteur = 0
    
    if CONFIG["MODE_LOCAL"]:
        print("[INFO] Mode Local : Pas de telechargement.")

    with requests.Session() as s:
        for titre, meta in flux.items():
            compteur += 1
            json_text = meta.get("json_content")
            
            # Gestion téléchargement lent vs cache rapide
            doit_telecharger = (not json_text and not CONFIG["MODE_LOCAL"])
            
            if doit_telecharger:
                try:
                    print(f"[{compteur}/{total_bulletins}] Telechargement : {titre[:40]}...")
                    resp = s.get(meta["link"] + "json/", timeout=10)
                    if resp.status_code == 200:
                        json_text = resp.text
                        meta["json_content"] = json_text
                        save_functions.sauvegarder_dict_en_json(flux, f"flux_{nom_flux.lower()}.json")
                    time.sleep(0.2)
                except: pass
            
            elif compteur % 10 == 0:
                print(f"[{compteur}/{total_bulletins}] Analyse locale...")

            if json_text:
                cves = list(set(re.findall(CVE_PATTERN, json_text)))
                resultat[titre] = cves
                total_cve += len(cves)

    print(f"[INFO] CVE totales trouvees ({nom_flux}): {total_cve}")
    return resultat

def enrichir_cve(cve_id, session):
    result = {
        "description": "Non disponible", "cvss_score": "Non disponible",
        "cwe": "Non disponible", "cwe_desc": "Non disponible",
        "products": [], "epss_score": "Non disponible"
    }

    # MITRE
    try:
        data = session.get(CVE_API + cve_id, timeout=10).json()
        cna = data["containers"]["cna"]
        desc = cna.get("descriptions", [{}])[0]
        result["description"] = desc.get("value", "Non disponible")
        
        metrics = cna.get("metrics", [{}])[0]
        if "cvssV3_1" in metrics: result["cvss_score"] = metrics["cvssV3_1"].get("baseScore")
        elif "cvssV3_0" in metrics: result["cvss_score"] = metrics["cvssV3_0"].get("baseScore")

        cwe_list, cwe_desc_list = [], []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                if desc.get("cweId"):
                    cwe_list.append(desc.get("cweId"))
                    cwe_desc_list.append(desc.get("description", ""))
        
        result["cwe"] = ", ".join(cwe_list) if cwe_list else "Non disponible"
        result["cwe_desc"] = " | ".join(cwe_desc_list) if cwe_desc_list else "Non disponible"

        for p in cna.get("affected", []):
            result["products"].append({
                "vendor": p.get("vendor"), "product": p.get("product"),
                "versions": [v.get("version") for v in p.get("versions", []) if v.get("status") == "affected"]
            })
    except: pass
    time.sleep(0.1)

    # EPSS
    try:
        epss = session.get(EPSS_API + cve_id, timeout=10).json()
        result["epss_score"] = epss["data"][0]["epss"]
    except: pass

    return result

def enrichir_toutes_les_cve(flux_cve, cache, label, jours_rafraichissement=30):
    print(f"[INFO] Enrichissement des CVE ({label})...")
    total = sum(len(v) for v in flux_cve.values())
    compteur = 0
    maintenant = datetime.now()

    with requests.Session() as session:
        for cve_list in flux_cve.values():
            for cve_id in cve_list:
                compteur += 1
                maj_necessaire = False
                if cve_id not in cache:
                    maj_necessaire = True
                else:
                    last_update = cache[cve_id].get("last_update")
                    if last_update:
                        delta = maintenant - datetime.strptime(last_update, "%Y-%m-%d")
                        if delta.days >= jours_rafraichissement: maj_necessaire = True
                
                if maj_necessaire:
                    if compteur % 5 == 0: 
                        print(f"Traitement... {compteur}/{total}")
                    
                    cache[cve_id] = {
                        "data": enrichir_cve(cve_id, session),
                        "last_update": time.strftime("%Y-%m-%d")
                    }
                    save_functions.sauvegarder_dict_en_json(cache, "details_cve_anssi.json")

def calculer_severity(cvss, epss):
    try: cvss = float(cvss)
    except: cvss = None
    try: epss = float(epss)
    except: epss = None

    if cvss is None and epss is None: return "Non disponible"
    if cvss is not None:
        if cvss >= 9: return "Critique"
        elif cvss >= 7: return "Haute"
        elif cvss >= 4: return "Moyenne"
        else: return "Faible"
    if epss is not None:
        if epss >= 0.8: return "Critique"
        elif epss >= 0.5: return "Haute"
        elif epss >= 0.2: return "Moyenne"
        else: return "Faible"

def extraire_id_anssi_from_link(link):
    pattern = r"(CERTFR-[\w-]+)"
    match = re.search(pattern, link)
    return match.group(1) if match else "Non disponible"

def recuperer_cisa_kev():
    print_step("Recuperation du catalogue CISA KEV (Exploitation active)")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        # On cree un SET (liste unique) des CVE pour une recherche rapide
        cisa_cves = {vuln['cveID'] for vuln in data['vulnerabilities']}
        print(f"[INFO] {len(cisa_cves)} vulnerabilites exploitees recensees par la CISA.")
        return cisa_cves
        
    except Exception as e:
        print(f"[ERREUR] Impossible de recuperer CISA KEV : {e}")
        return set()

def add_rows(rows, flux, flux_cve, cache, type_bulletin,cisa_set=None):
    if cisa_set is None:
        cisa_set = set()
    print_step(f"Construction des lignes ({type_bulletin})")
    for titre, meta in flux.items():
        lien_anssi = meta.get("link", "")
        id_anssi = extraire_id_anssi_from_link(lien_anssi)
        
        for cve in flux_cve.get(titre, []):
            cache_entry = cache.get(cve, {})
            details = cache_entry.get("data", cache_entry) if "data" in cache_entry else cache_entry
            if not details: details = {}
            
            produits = details.get("products", [])
            if not produits: produits = [{"vendor": "ND", "product": "ND", "versions": []}]

            # Verification si la CVE est dans la liste CISA
            exploitation_active = "OUI" if cve in cisa_set else "Non"

            for p in produits:
                vendor = p.get("vendor", "ND") if isinstance(p, dict) else "ND"
                produit = (p.get("product") or p.get("product_name", "ND")) if isinstance(p, dict) else "ND"
                versions = p.get("versions", []) if isinstance(p, dict) else []

                rows.append({
                    "ID ANSSI": id_anssi,
                    "Exploitation Active (CISA)": exploitation_active,
                    "Titre du bulletin (ANSSI)": titre,
                    "Type de bulletin": type_bulletin,
                    "Date de publication": meta.get("published"),
                    "Identifiant CVE": cve,
                    "Score CVSS": details.get("cvss_score"),
                    "Type CWE": details.get("cwe"),
                    "Score EPSS": details.get("epss_score"),
                    "Lien du bulletin (ANSSI)": lien_anssi,
                    "Description": details.get("description"),
                    "Editeur/Vendor": vendor,
                    "Produit": produit,
                    "Versions affectees": ", ".join(versions),
                    "Severity": calculer_severity(details.get("cvss_score"), details.get("epss_score"))
                })
    print("[OK] Tableau construit")

def detecter_alertes(df):
    # Conversion numérique sécurisée
    df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
    df["Score EPSS"] = pd.to_numeric(df["Score EPSS"], errors="coerce")

    return df[
        (df["Type de bulletin"] == "Alerte") & 
        (
            (df["Score CVSS"] >= 9) | 
            (df["Score EPSS"] >= 0.8) |
            (df["Exploitation Active (CISA)"] == "OUI")
        )
    ]

def construire_message_alerte(df_alertes):
    message = (
    "Objet : Alerte de sécurité – Vulnérabilités critiques détectées\n\n"
    "Bonjour,\n\n"
    "Dans le cadre de notre veille de sécurité, nous avons identifié une ou plusieurs "
    "vulnérabilités critiques NOUVELLES susceptibles d’impacter votre système d’information.\n\n"
    "Vous trouverez ci-dessous le détail des vulnérabilités détectées.\n"
    "==========================================\n\n"
)

    for _, row in df_alertes.iterrows():
        marqueur_cisa = (
            "[!!! EXPLOITATION ACTIVE CONFIRMÉE !!!]"
            if row['Exploitation Active (CISA)'] == "OUI"
            else ""
        )

        message += (
            f"CVE : {row['Identifiant CVE']} {marqueur_cisa}\n"
            f"Produit concerné : {row['Produit']}\n"
            f"Éditeur : {row['Editeur/Vendor']}\n"
            f"Score CVSS : {row['Score CVSS']}\n"
            f"Score EPSS : {row['Score EPSS']}\n"
            f"Exploitation active (CISA) : {row['Exploitation Active (CISA)']}\n"
            f"Type de vulnérabilité (CWE) : {row['Type CWE']}\n"
            f"Bulletin ANSSI : {row['Lien du bulletin (ANSSI)']}\n"
            "------------------------------------------\n"
        )

    message += (
        "\nNous vous recommandons d’évaluer rapidement l’exposition de vos systèmes "
        "et d’appliquer les correctifs ou mesures de mitigation appropriées.\n\n"
        "Cordialement,\n\n"
        "Équipe Sécurité\n"
        "Projet_Alertes_Anssi\n"
    )
    return message

def envoyer_email_brevo_liste(liste_destinataires, sujet, message):
    """ Envoi du mail à une liste de destinataires via boucle. Retourne True si connexion OK. """
    success = False
    try:
        # 1. Connexion unique
        server = smtplib.SMTP(CONFIG["SMTP_SERVER"], CONFIG["SMTP_PORT"])
        server.starttls()
        server.login(CONFIG["BREVO_SMTP_LOGIN"], CONFIG["BREVO_API_KEY"])
        print("[INFO] Connexion SMTP établie.")
        success = True # On considère que si on arrive ici, le système de mail fonctionne

        # 2. Boucle d'envoi
        for dest in liste_destinataires:
            dest = dest.strip() # Nettoyage des espaces
            if not dest: continue

            try:
                msg = MIMEText(message, 'plain', 'utf-8')
                msg["From"] = CONFIG["BREVO_SENDER_EMAIL"]
                msg["To"] = dest
                msg["Subject"] = Header(sujet, 'utf-8')

                server.sendmail(CONFIG["BREVO_SENDER_EMAIL"], dest, msg.as_string())
                print(f"[SUCCES] Email envoyé à {dest}")
            except Exception as e_indiv:
                print(f"[ERREUR] Echec envoi pour {dest} : {e_indiv}")

        server.quit()
        print("[INFO] Connexion SMTP fermée.")

    except Exception as e:
        print(f"[ERREUR CRITIQUE] Echec connexion SMTP : {e}")
        success = False
    
    return success

# ================== INTERFACE GRAPHIQUE ==================

class TextRedirector(object):
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag

    def write(self, str_text):
        self.widget.configure(state="normal")
        
        if "[ERREUR]" in str_text or "Echec" in str_text: tag_to_use = "err"
        elif "[ALERTE]" in str_text or "CRITIQUE" in str_text: tag_to_use = "warn"
        elif "[SUCCES]" in str_text or "[OK]" in str_text: tag_to_use = "info"
        else: tag_to_use = self.tag

        self.widget.insert("end", str_text, (tag_to_use,))
        self.widget.see("end")
        self.widget.configure(state="disabled")
        self.widget.update_idletasks()

    def flush(self): pass

class VulnerabilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ESILV - Scanner Vulnérabilités ANSSI")
        self.root.geometry("1050x850")
        self.root.configure(bg=COULEURS["bg_app"])
        
        self.df_result = None 

        self.style_interface()
        self.setup_ui()

    def style_interface(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background=COULEURS["bg_app"])
        style.configure("Card.TFrame", background=COULEURS["bg_panel"], relief="flat")
        style.configure("TLabelframe", background=COULEURS["bg_panel"], relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=COULEURS["bg_panel"], foreground=COULEURS["primary"], font=POLICE_TITRE)
        style.configure("TLabel", background=COULEURS["bg_panel"], foreground=COULEURS["text"], font=POLICE_TEXTE)
        style.configure("AppTitle.TLabel", background=COULEURS["bg_app"], foreground=COULEURS["primary"], font=("Segoe UI", 18, "bold"))
        style.configure("Bg.TLabel", background=COULEURS["bg_app"])
        style.configure("Primary.TButton", background=COULEURS["primary"], foreground="white", font=POLICE_BOUTON, borderwidth=0, padding=10)
        style.map("Primary.TButton", background=[('active', COULEURS["primary_hover"])])
        style.configure("Secondary.TButton", background="#bdc3c7", foreground=COULEURS["text"], font=POLICE_BOUTON, borderwidth=0, padding=10)

    def setup_ui(self):
        # En-tête
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill="x", padx=20, pady=20)
        ttk.Label(header_frame, text="Scanner de Vulnérabilités & Alerting", style="AppTitle.TLabel").pack(side="left")
        
        # --- Zone Configuration ---
        config_card = ttk.LabelFrame(self.root, text=" Configuration & Paramètres ", padding=20)
        config_card.pack(fill="x", padx=20, pady=5)

        ttk.Label(config_card, text="Clé API Brevo (SMTP):").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_key = ttk.Entry(config_card, width=60, show="●")
        self.entry_key.insert(0, "xsmtpsib-49ead3b448981f859e516f2bc8b0c48ed7d9fbfa8ef31b438282c7029593dff4-KFGR3G3bkoUDWykg") 
        self.entry_key.grid(row=0, column=1, padx=15, pady=5)

        ttk.Label(config_card, text="Email Expéditeur:").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_sender = ttk.Entry(config_card, width=60)
        self.entry_sender.insert(0, CONFIG["BREVO_SENDER_EMAIL"])
        self.entry_sender.grid(row=1, column=1, padx=15, pady=5)

        ttk.Label(config_card, text="Mailing List (séparés par ,):").grid(row=2, column=0, sticky="w", pady=5)
        self.entry_recipients = ttk.Entry(config_card, width=60)
        # Valeur par défaut
        default_list = "projet.alertes.esilv+test1@gmail.com, projet.alertes.esilv+test2@gmail.com, projet.alertes.esilv+test3@gmail.com"
        self.entry_recipients.insert(0, default_list)
        self.entry_recipients.grid(row=2, column=1, padx=15, pady=5)
        
        self.var_local = tk.BooleanVar(value=CONFIG["MODE_LOCAL"])
        ttk.Checkbutton(config_card, text="Mode Hors-Ligne (Fichiers locaux uniquement)", variable=self.var_local, style="TCheckbutton").grid(row=3, column=1, sticky="w", pady=10)

        # --- Zone Actions ---
        action_frame = ttk.Frame(self.root, style="TFrame")
        action_frame.pack(fill="x", padx=20, pady=15)

        self.btn_run = ttk.Button(action_frame, text="LANCER L'ANALYSE", style="Primary.TButton", command=self.lancer_analyse)
        self.btn_run.pack(side="left", padx=(0, 10))

        self.btn_show_df = ttk.Button(action_frame, text="Afficher les données", style="Secondary.TButton", command=self.afficher_dataframe, state="disabled")
        self.btn_show_df.pack(side="left")

        # --- Zone Logs ---
        log_label = ttk.Label(self.root, text="Journal d'exécution", style="Bg.TLabel", font=("Segoe UI", 10, "bold"))
        log_label.pack(anchor="w", padx=20, pady=(10, 0))

        frame_log = ttk.Frame(self.root, style="TFrame")
        frame_log.pack(fill="both", expand=True, padx=20, pady=5)

        self.log_widget = scrolledtext.ScrolledText(frame_log, state='disabled', height=15, 
                                                    bg=COULEURS["log_bg"], fg=COULEURS["log_text"], 
                                                    font=("Consolas", 10), borderwidth=0)
        self.log_widget.pack(fill="both", expand=True)

        self.log_widget.tag_config("info", foreground=COULEURS["log_info"])
        self.log_widget.tag_config("warn", foreground=COULEURS["log_warn"])
        self.log_widget.tag_config("err", foreground=COULEURS["log_err"])
        self.log_widget.tag_config("stdout", foreground=COULEURS["log_text"])

        sys.stdout = TextRedirector(self.log_widget, "stdout")
        sys.stderr = TextRedirector(self.log_widget, "err")

    def lancer_analyse(self):
        # Mise à jour de la configuration
        CONFIG["BREVO_API_KEY"] = self.entry_key.get()
        CONFIG["BREVO_SENDER_EMAIL"] = self.entry_sender.get()
        CONFIG["MODE_LOCAL"] = self.var_local.get()
        
        # Traitement de la liste
        raw_recipients = self.entry_recipients.get()
        # On remplace les points-virgules par des virgules, puis on coupe
        liste_propre = [email.strip() for email in raw_recipients.replace(';', ',').split(',') if email.strip()]
        CONFIG["ALERT_MAILING_LIST"] = liste_propre

        self.btn_run.config(state="disabled")
        self.btn_show_df.config(state="disabled")
        self.log_widget.configure(state='normal')
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.configure(state='disabled')

        threading.Thread(target=self.run_pipeline, daemon=True).start()

    def run_pipeline(self):
        try:
            print("[INFO] DEMARRAGE DU PIPELINE")
            
            # 1. Flux RSS
            flux_alerte, flux_avis = recupFlux()
            
            # 2. CISA KEV (Nouveau)
            set_cisa_kev = recuperer_cisa_kev()

            flux_alerte = save_functions.charger_json_en_dict("flux_alerte.json")
            flux_avis = save_functions.charger_json_en_dict("flux_avis.json")

            flux_alerte_cve = extraire_cves_depuis_flux(flux_alerte, "alerte")
            flux_avis_cve = extraire_cves_depuis_flux(flux_avis, "avis")

            cve_cache = save_functions.charger_json_en_dict("details_cve_anssi.json")
            enrichir_toutes_les_cve(flux_alerte_cve, cve_cache, "alerte")
            enrichir_toutes_les_cve(flux_avis_cve, cve_cache, "avis")

            rows = []
            add_rows(rows, flux_alerte, flux_alerte_cve, cve_cache, "Alerte", set_cisa_kev)
            add_rows(rows, flux_avis, flux_avis_cve, cve_cache, "Avis", set_cisa_kev)

            self.df_result = pd.DataFrame(rows)
            self.df_result.to_csv("anssi_cve_dataframe.csv", index=False)
            save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

            print_step("PIPELINE TERMINE")
            print(f"Total lignes generees : {self.df_result.shape[0]}")

            # ================= GESTION DES NOUVELLES ALERTES =================
            print_step("ANALYSE DES ALERTES")
            
            # 1. Charger l'historique
            history_data = save_functions.charger_json_en_dict(HISTORY_FILE)
            if history_data is None: history_data = {"sent_ids": []}
            sent_ids_set = set(history_data.get("sent_ids", []))

            # 2. Détecter toutes les alertes critiques
            df_alertes_all = detecter_alertes(self.df_result)
            
            # 3. Filtrer pour garder uniquement les nouvelles
            nouvelles_alertes_rows = []
            new_ids_to_add = []

            if not df_alertes_all.empty:
                for index, row in df_alertes_all.iterrows():
                    # Création ID unique : Lien Bulletin + CVE
                    unique_id = f"{row['Lien du bulletin (ANSSI)']}::{row['Identifiant CVE']}"
                    
                    if unique_id not in sent_ids_set:
                        nouvelles_alertes_rows.append(row)
                        new_ids_to_add.append(unique_id)
            
            df_nouvelles = pd.DataFrame(nouvelles_alertes_rows)

            if not df_nouvelles.empty:
                print(f"[ALERTE] {df_nouvelles.shape[0]} NOUVELLES vulnerabilites CRITIQUES.")
                message = construire_message_alerte(df_nouvelles)
                
                # Envoi Email
                if CONFIG["BREVO_API_KEY"] and CONFIG["BREVO_SENDER_EMAIL"] and CONFIG["ALERT_MAILING_LIST"]:
                    sujet = f"ALERTE SECURITE : {df_nouvelles.shape[0]} Nouvelles Failles Critiques"
                    print(f"[INFO] Envoi aux destinataires : {CONFIG['ALERT_MAILING_LIST']}")
                    
                    # Si l'envoi réussit, on met à jour l'historique
                    if envoyer_email_brevo_liste(CONFIG["ALERT_MAILING_LIST"], sujet, message):
                        sent_ids_set.update(new_ids_to_add)
                        history_data["sent_ids"] = list(sent_ids_set)
                        save_functions.sauvegarder_dict_en_json(history_data, HISTORY_FILE)
                        print(f"[INFO] Historique mis à jour ({len(new_ids_to_add)} ajouts).")
                else:
                    print("[ERREUR] Impossible d'envoyer l'email : Config incomplete ou liste vide.")
            else:
                print("[INFO] Aucune NOUVELLE alerte critique depuis le dernier envoi.")
            
            self.root.after(0, self.fin_analyse_succes)

        except Exception as e:
            print(f"[ERREUR FATALE] {e}")
            import traceback
            traceback.print_exc()
            self.root.after(0, lambda: self.btn_run.config(state="normal"))

    def fin_analyse_succes(self):
        self.btn_run.config(state="normal")
        self.btn_show_df.config(state="normal")
        messagebox.showinfo("Succes", "L'analyse est terminee.\nConsultez les logs pour les details.")

    def afficher_dataframe(self):
        if self.df_result is None or self.df_result.empty:
            messagebox.showinfo("Info", "Aucune donnee a afficher.")
            return
            
        top = tk.Toplevel(self.root)
        top.title("Resultats de l'analyse")
        top.geometry("1200x600")
        top.configure(bg=COULEURS["bg_app"])

        frame_tv = ttk.Frame(top)
        frame_tv.pack(fill="both", expand=True, padx=10, pady=10)

        scroll_y = ttk.Scrollbar(frame_tv, orient="vertical")
        scroll_x = ttk.Scrollbar(frame_tv, orient="horizontal")

        columns = list(self.df_result.columns)
        tree = ttk.Treeview(frame_tv, columns=columns, show="headings", 
                            yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        scroll_y.config(command=tree.yview)
        scroll_x.config(command=tree.xview)
        scroll_y.pack(side="right", fill="y")
        scroll_x.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150, minwidth=50)

        for index, row in self.df_result.iterrows():
            values = [str(val) for val in row.tolist()]
            tree.insert("", "end", values=values)

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityApp(root)
    root.mainloop()
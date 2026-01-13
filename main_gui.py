import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import sys
import os

# Vos imports d'origine
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

# ================== CONFIGURATION DU DESIGN ==================

COULEURS = {
    "bg_app": "#f4f6f9",        # Gris très clair pour le fond
    "bg_panel": "#ffffff",      # Blanc pour les cadres
    "primary": "#2c3e50",       # Bleu nuit (Boutons, titres)
    "primary_hover": "#34495e", # Bleu nuit plus clair
    "accent": "#e74c3c",        # Rouge (Alertes)
    "text": "#2c3e50",          # Texte principal
    "log_bg": "#1e1e1e",        # Fond du terminal (Logs)
    "log_text": "#d4d4d4",      # Texte du terminal
    "log_info": "#61afef",      # Bleu clair (Info logs)
    "log_warn": "#e5c07b",      # Jaune (Warning)
    "log_err": "#e06c75"        # Rouge (Erreur)
}

POLICE_TITRE = ("Segoe UI", 12, "bold")
POLICE_TEXTE = ("Segoe UI", 10)
POLICE_BOUTON = ("Segoe UI", 10, "bold")

# ================== VARIABLES GLOBALES ==================

CONFIG = {
    "BREVO_SMTP_LOGIN": "9fb516001@smtp-brevo.com",
    "BREVO_API_KEY": "", 
    "BREVO_SENDER_EMAIL": "projet.alertes.esilv@gmail.com",
    "ALERT_RECIPIENT": "m.diawarapro2005@gmail.com",
    "MODE_LOCAL": False,
    "SMTP_SERVER": "smtp-relay.brevo.com",
    "SMTP_PORT": 587
}

# URLs fixes
RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
CVE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"

# ================== FONCTIONS LOGIQUES (NETTOYÉES) ==================

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
    
    print("\n[RESUME ETAPE 1]")
    print(f"Alertes recuperees : {len(rss_alertes)}")
    print(f"Avis recuperes     : {len(rss_avis)}")
    return rss_alertes, rss_avis

def extraire_cves_depuis_flux(flux, nom_flux):
    print_step(f"Extraction des CVE : {nom_flux}")
    resultat = {}
    total_cve = 0
    
    if CONFIG["MODE_LOCAL"]:
        print("[INFO] Mode Local : Pas de telechargement de JSON additionnel.")

    with requests.Session() as s:
        for titre, meta in flux.items():
            json_text = meta.get("json_content")
            
            if not json_text and not CONFIG["MODE_LOCAL"]:
                try:
                    resp = s.get(meta["link"] + "json/", timeout=10)
                    if resp.status_code == 200:
                        json_text = resp.text
                        meta["json_content"] = json_text
                        save_functions.sauvegarder_dict_en_json(flux, f"flux_{nom_flux.lower()}.json")
                    time.sleep(0.2)
                except: pass
            
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
                    # Affichage simplifié pour les logs
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


def add_rows(rows, flux, flux_cve, cache, type_bulletin):

    print_step(f"Etape 4 -- Construction des lignes ({type_bulletin})")

    bulletin_total = len(flux)
    compteur = 0

    for titre, meta in flux.items():
        compteur += 1
        
        # 1. Extraction de l'ID ANSSI depuis le lien
        lien_anssi = meta.get("link", "")
        id_anssi = extraire_id_anssi_from_link(lien_anssi)

        for cve in flux_cve.get(titre, []):
            
            cache_entry = cache.get(cve, {})
            details = cache_entry.get("data", cache_entry) if "data" in cache_entry else cache_entry
            
            if not details: details = {}

            produits = details.get("products", [])

            if not produits:
                produits = [{"vendor": "Non disponible", "product": "Non disponible", "versions": []}]

            for p in produits:
                if not isinstance(p, dict):
                    vendor, produit, versions = "Non disponible", "Non disponible", []
                else:
                    vendor = p.get("vendor", "Non disponible")
                    produit = p.get("product") or p.get("product_name", "Non disponible")
                    versions = p.get("versions", [])

                # 2. Ajout de la colonne ID ANSSI en premier
                rows.append({
                    "ID ANSSI": id_anssi,  # <--- NOUVELLE COLONNE ICI
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

    print("\nTableau construit\n")

def detecter_alertes(df):
    return df[
        (pd.to_numeric(df["Score CVSS"], errors="coerce") >= 9) &
        (pd.to_numeric(df["Score EPSS"], errors="coerce") >= 0.8) &
        (df["Type de bulletin"] == "Alerte")
    ]

def construire_message_alerte(df_alertes):
    message = "ALERTE DE SECURITE -- Vulnerabilites critiques detectees \n\n"
    for _, row in df_alertes.iterrows():
        message += (
            f"Identifiant CVE : {row['Identifiant CVE']}\n"
            f"Produit : {row['Produit']}\n"
            f"Editeur/Vendor : {row['Editeur/Vendor']}\n"
            f"Score CVSS : {row['Score CVSS']}\n"
            f"Score EPSS : {row['Score EPSS']}\n"
            f"Type CWE : {row['Type CWE']}\n"
            f"Lien du bulletin (ANSSI) : {row['Lien du bulletin (ANSSI)']}\n"
            "------------------------------------------\n"
        )
    return message

def envoyer_email_brevo(destinataire, sujet, message):
    msg = MIMEText(message, 'plain', 'utf-8')
    msg["From"] = CONFIG["BREVO_SENDER_EMAIL"]
    msg["To"] = destinataire
    msg["Subject"] = Header(sujet, 'utf-8')

    try:
        server = smtplib.SMTP(CONFIG["SMTP_SERVER"], CONFIG["SMTP_PORT"])
        server.starttls()
        server.login(CONFIG["BREVO_SMTP_LOGIN"], CONFIG["BREVO_API_KEY"])
        server.sendmail(CONFIG["BREVO_SENDER_EMAIL"], destinataire, msg.as_string())
        server.quit()
        print(f"[SUCCES] Email envoye via Brevo a {destinataire}")
    except Exception as e:
        print(f"[ERREUR] Echec de l'envoi via Brevo : {e}")

# ================== INTERFACE GRAPHIQUE (DESIGN AMÉLIORÉ) ==================

class TextRedirector(object):
    """Redirige les print() vers le widget de logs avec couleurs"""
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag

    def write(self, str_text):
        self.widget.configure(state="normal")
        
        # Coloration syntaxique basique
        if "[ERREUR]" in str_text or "Echec" in str_text:
            tag_to_use = "err"
        elif "[ALERTE]" in str_text or "CRITIQUE" in str_text:
            tag_to_use = "warn"
        elif "[SUCCES]" in str_text or "[OK]" in str_text:
            tag_to_use = "info"
        else:
            tag_to_use = self.tag

        self.widget.insert("end", str_text, (tag_to_use,))
        self.widget.see("end")
        self.widget.configure(state="disabled")
        self.widget.update_idletasks()

    def flush(self):
        pass

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
        
        # Configuration des cadres
        style.configure("TFrame", background=COULEURS["bg_app"])
        style.configure("Card.TFrame", background=COULEURS["bg_panel"], relief="flat")
        
        # Configuration des LabelFrame
        style.configure("TLabelframe", background=COULEURS["bg_panel"], relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=COULEURS["bg_panel"], foreground=COULEURS["primary"], font=POLICE_TITRE)
        
        # Configuration des Labels
        style.configure("TLabel", background=COULEURS["bg_panel"], foreground=COULEURS["text"], font=POLICE_TEXTE)
        style.configure("AppTitle.TLabel", background=COULEURS["bg_app"], foreground=COULEURS["primary"], font=("Segoe UI", 18, "bold"))
        style.configure("Bg.TLabel", background=COULEURS["bg_app"])

        # Configuration des Boutons
        style.configure("Primary.TButton", 
                        background=COULEURS["primary"], 
                        foreground="white", 
                        font=POLICE_BOUTON, 
                        borderwidth=0, 
                        padding=10)
        style.map("Primary.TButton", 
                  background=[('active', COULEURS["primary_hover"])])
        
        style.configure("Secondary.TButton", 
                        background="#bdc3c7", 
                        foreground=COULEURS["text"], 
                        font=POLICE_BOUTON, 
                        borderwidth=0, 
                        padding=10)

    def setup_ui(self):
        # En-tête
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill="x", padx=20, pady=20)
        
        ttk.Label(header_frame, text="Scanner de Vulnérabilités & Alerting", style="AppTitle.TLabel").pack(side="left")
        
        # --- Zone Configuration ---
        config_card = ttk.LabelFrame(self.root, text=" Configuration & Paramètres ", padding=20)
        config_card.pack(fill="x", padx=20, pady=5)

        # Grille de formulaire
        ttk.Label(config_card, text="Clé API Brevo (SMTP):").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_key = ttk.Entry(config_card, width=60, show="●")
        self.entry_key.insert(0, "xsmtpsib-49ead3b448981f859e516f2bc8b0c48ed7d9fbfa8ef31b438282c7029593dff4-KFGR3G3bkoUDWykg") 
        self.entry_key.grid(row=0, column=1, padx=15, pady=5)

        ttk.Label(config_card, text="Email Expéditeur (Validé):").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_sender = ttk.Entry(config_card, width=60)
        self.entry_sender.insert(0, CONFIG["BREVO_SENDER_EMAIL"])
        self.entry_sender.grid(row=1, column=1, padx=15, pady=5)

        ttk.Label(config_card, text="Email Destinataire (Alerte):").grid(row=2, column=0, sticky="w", pady=5)
        self.entry_recipient = ttk.Entry(config_card, width=60)
        self.entry_recipient.insert(0, CONFIG["ALERT_RECIPIENT"])
        self.entry_recipient.grid(row=2, column=1, padx=15, pady=5)
        
        # Checkbox stylisée
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

        frame_log = ttk.Frame(self.root, style="TFrame") # Conteneur pour le padding
        frame_log.pack(fill="both", expand=True, padx=20, pady=5)

        self.log_widget = scrolledtext.ScrolledText(frame_log, state='disabled', height=15, 
                                                    bg=COULEURS["log_bg"], fg=COULEURS["log_text"], 
                                                    font=("Consolas", 10), borderwidth=0)
        self.log_widget.pack(fill="both", expand=True)

        # Tags de couleurs pour les logs
        self.log_widget.tag_config("info", foreground=COULEURS["log_info"])
        self.log_widget.tag_config("warn", foreground=COULEURS["log_warn"])
        self.log_widget.tag_config("err", foreground=COULEURS["log_err"])
        self.log_widget.tag_config("stdout", foreground=COULEURS["log_text"])

        # Redirection stdout
        sys.stdout = TextRedirector(self.log_widget, "stdout")
        sys.stderr = TextRedirector(self.log_widget, "err")

    def lancer_analyse(self):
        CONFIG["BREVO_API_KEY"] = self.entry_key.get()
        CONFIG["BREVO_SENDER_EMAIL"] = self.entry_sender.get()
        CONFIG["ALERT_RECIPIENT"] = self.entry_recipient.get()
        CONFIG["MODE_LOCAL"] = self.var_local.get()

        self.btn_run.config(state="disabled")
        self.btn_show_df.config(state="disabled")
        self.log_widget.configure(state='normal')
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.configure(state='disabled')

        threading.Thread(target=self.run_pipeline, daemon=True).start()

    def run_pipeline(self):
        try:
            print("[INFO] DEMARRAGE DU PIPELINE")
            
            flux_alerte, flux_avis = recupFlux()
            flux_alerte = save_functions.charger_json_en_dict("flux_alerte.json")
            flux_avis = save_functions.charger_json_en_dict("flux_avis.json")

            flux_alerte_cve = extraire_cves_depuis_flux(flux_alerte, "alerte")
            flux_avis_cve = extraire_cves_depuis_flux(flux_avis, "avis")

            cve_cache = save_functions.charger_json_en_dict("details_cve_anssi.json")
            enrichir_toutes_les_cve(flux_alerte_cve, cve_cache, "alerte")
            enrichir_toutes_les_cve(flux_avis_cve, cve_cache, "avis")

            rows = []
            add_rows(rows, flux_alerte, flux_alerte_cve, cve_cache, "Alerte")
            add_rows(rows, flux_avis, flux_avis_cve, cve_cache, "Avis")

            self.df_result = pd.DataFrame(rows)
            self.df_result.to_csv("anssi_cve_dataframe.csv", index=False)
            save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

            print_step("PIPELINE TERMINE")
            print(f"Total lignes generees : {self.df_result.shape[0]}")

            print_step("ANALYSE DES ALERTES")
            df_alertes = detecter_alertes(self.df_result)

            if not df_alertes.empty:
                print(f"[ALERTE] {df_alertes.shape[0]} vulnerabilites CRITIQUES detectees.")
                message = construire_message_alerte(df_alertes)
                
                if CONFIG["BREVO_API_KEY"] and CONFIG["BREVO_SENDER_EMAIL"] and CONFIG["ALERT_RECIPIENT"]:
                    sujet = f"ALERTE SECURITE : {df_alertes.shape[0]} Failles Critiques"
                    envoyer_email_brevo(CONFIG["ALERT_RECIPIENT"], sujet, message)
                else:
                    print("[ERREUR] Impossible d'envoyer l'email : Config incomplete.")
            else:
                print("[INFO] Aucune alerte critique.")
            
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
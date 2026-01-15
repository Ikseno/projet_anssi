import feedparser
import requests
import re
import pandas as pd
import time
from datetime import datetime, timedelta
import save_functions
import smtplib
from email.mime.text import MIMEText
import os # Ajouté pour gérer l'existence du fichier historique

# ================== CONSTANTES CONFIGURATION ==================

BREVO_SMTP_LOGIN = "9fb516001@smtp-brevo.com"
BREVO_API_KEY = "xsmtpsib-49ead3b448981f859e516f2bc8b0c48ed7d9fbfa8ef31b438282c7029593dff4-KFGR3G3bkoUDWykg"
BREVO_SENDER_EMAIL = "projet.alertes.esilv@gmail.com"

ALERT_MAILING_LIST = [
    "projet.alertes.esilv+test1@gmail.com",
    "projet.alertes.esilv+test2@gmail.com",
    "projet.alertes.esilv+test3@gmail.com"
]

MODE_LOCAL = False
RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"

# APIs
CVE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587 

# Fichier pour stocker l'historique des alertes envoyées
HISTORY_FILE = "alert_history.json"

# ================== AFFICHAGE ==================

def print_step(titre):
    print("\n" + "="*70)
    print(titre)
    print("="*70)

# ================== 1 RECUPERATION FLUX RSS ==================

def recupFlux():
    print_step("Etape 1 -- Recuperation des flux RSS ANSSI (ONLINE ou LOCAL)")
    headers = {"User-Agent": "Mozilla/5.0 (ESILV Student Project)"}

    def charger(url, label, fichier_cache):
        flux_cache = save_functions.charger_json_en_dict(fichier_cache) or {}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            rss = feedparser.parse(resp.text)
            nb = len(rss.entries)
            print(f"{nb} entrees trouvees dans {label}")

            maj = False
            for e in rss.entries:
                if e.title not in flux_cache:
                    flux_cache[e.title] = {
                        "description": e.description,
                        "link": e.link,
                        "published": e.published,
                        "json_content": None
                    }
                    maj = True
                    print(f"  Nouveau bulletin ajoute : {e.title}")
                else:
                    cached_date = flux_cache[e.title].get("published")
                    if cached_date != e.published:
                        flux_cache[e.title].update({
                            "description": e.description,
                            "link": e.link,
                            "published": e.published,
                            "json_content": None
                        })
                        maj = True
                        print(f"  Bulletin mis a jour : {e.title}")
            time.sleep(0.2)

            if maj:
                save_functions.sauvegarder_dict_en_json(flux_cache, fichier_cache)
                print(f"Flux {label} mis a jour dans {fichier_cache}")
            else:
                print(f" Pas de nouveaute pour {label}, cache inchange")

            return flux_cache
        except Exception as e:
            print(f"Erreur lors du chargement de {label} : {e}")
            return flux_cache

    rss_alertes = charger(RSS_ALERTES, "Alertes ANSSI", "flux_alerte.json")
    rss_avis = charger(RSS_AVIS, "Avis ANSSI", "flux_avis.json")

    print("\nRESUME DE L'ETAPE 1")
    print("----------------------------")
    print(f"{len(rss_alertes)} alertes recuperees")
    print(f"{len(rss_avis)} avis recuperes")

    return rss_alertes, rss_avis

# ================== 2 EXTRACTION DES CVE ==================

def extraire_cves_depuis_flux(flux, nom_flux):
    print_step(f" Etape 2 -- Extraction des CVE depuis : {nom_flux}")
    resultat = {}
    total_cve = 0
    bulletin_count = len(flux)

    print(f" {bulletin_count} bulletins a analyser\n")

    if MODE_LOCAL:
        print(" [INFO] Mode Local active : Pas de telechargement.")

    with requests.Session() as s:
        index = 0
        for titre, meta in flux.items():
            index += 1
            json_text = meta.get("json_content")
            cached_published = meta.get("cached_published")

            doit_telecharger = (not json_text or cached_published != meta["published"]) and not MODE_LOCAL

            if doit_telecharger:
                print(f" Bulletin {index}/{bulletin_count} : {titre}")
                try:
                    resp = s.get(meta["link"] + "json/", timeout=10)
                    resp.raise_for_status()
                    json_text = resp.text
                    meta["json_content"] = json_text
                    meta["cached_published"] = meta["published"]
                    save_functions.sauvegarder_dict_en_json(flux, f"flux_{nom_flux.lower()}.json")
                    print("    Bulletin telecharge ou mis a jour")
                    time.sleep(2)
                except Exception as e:
                    print(f"    Erreur : {e}")
                    json_text = ""
            
            elif index % 10 == 0:
                print(f" Bulletin {index}/{bulletin_count} : Traitement cache local...")

            if json_text:
                cves = list(set(re.findall(CVE_PATTERN, json_text)))
                resultat[titre] = cves
                total_cve += len(cves)
                if doit_telecharger:
                     print(f"    {len(cves)} CVE trouvees")

    print(f"\nRESUME ETAPE 2 -- {nom_flux}")
    print("--------------------------------")
    print(f" CVE totales trouvees : {total_cve}")
    return resultat

# ================== 3 ENRICHISSEMENT CVE (MITRE + NVD + EPSS) ==================

def enrichir_via_nvd(cve_id):
    """
    Tente de recuperer les infos manquantes via l'API NVD.
    Utile si MITRE n'a pas encore le CVSS ou le CWE.
    """
    url = f"{NVD_API_URL}{cve_id}"
    nvd_data = {"cvss": None, "cwe": None}
    
    try:
        # Pause pour respecter les limites API NVD (sans cle API = lent)
        time.sleep(0.6) 
        
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            
            if vulns:
                metrics = vulns[0]["cve"].get("metrics", {})
                weaknesses = vulns[0]["cve"].get("weaknesses", [])

                # 1. Recuperation CVSS (Priorite v3.1 > v3.0 > v2)
                if "cvssMetricV31" in metrics:
                    nvd_data["cvss"] = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    nvd_data["cvss"] = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    nvd_data["cvss"] = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                # 2. Recuperation CWE
                cwe_list = []
                for w in weaknesses:
                    for desc in w.get("description", []):
                        if desc.get("value", "").startswith("CWE-"):
                            cwe_list.append(desc.get("value"))
                
                if cwe_list:
                    nvd_data["cwe"] = ", ".join(list(set(cwe_list))) # Dedoublonnage

    except Exception as e:
        # NVD est souvent instable ou lent, on ne bloque pas le script pour ca
        pass
        
    return nvd_data

def enrichir_cve(cve_id, session):
    print(f"Recuperation details MITRE + NVD + FIRST pour {cve_id}")
    result = {
        "description": "Non disponible", "cvss_score": "Non disponible",
        "cwe": "Non disponible", "cwe_desc": "Non disponible",
        "products": [], "epss_score": "Non disponible"
    }
    
    # ---- 1. MITRE (Source Primaire) ----
    try:
        data = session.get(CVE_API + cve_id, timeout=10).json()
        cna = data["containers"]["cna"]
        desc = cna.get("descriptions", [{}])[0]
        result["description"] = desc.get("value", "Non disponible")
        metrics = cna.get("metrics", [{}])[0]

        if "cvssV3_1" in metrics:
            result["cvss_score"] = metrics["cvssV3_1"].get("baseScore")
        elif "cvssV3_0" in metrics:
            result["cvss_score"] = metrics["cvssV3_0"].get("baseScore")

        cwe_list = []
        cwe_desc_list = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    cwe_list.append(cwe_id)
                    cwe_desc_list.append(desc.get("description", ""))
        result["cwe"] = ", ".join(cwe_list) if cwe_list else "Non disponible"
        result["cwe_desc"] = " | ".join(cwe_desc_list) if cwe_desc_list else "Non disponible"

        for p in cna.get("affected", []):
            result["products"].append({
                "vendor": p.get("vendor"), "product": p.get("product"),
                "versions": [v.get("version") for v in p.get("versions", []) if v.get("status") == "affected"]
            })
        print("MITRE OK")
    except Exception as e:
        print(f"MITRE indisponible : {e}")
    
    time.sleep(0.1)

    # ---- 2. NVD (Source Secondaire - Fallback si donnees manquantes) ----
    # Si le CVSS ou le CWE manque cote MITRE, on tente la NVD
    if result["cvss_score"] == "Non disponible" or result["cwe"] == "Non disponible":
        print(f"   -> Donnees incompletes MITRE, tentative via NVD...")
        nvd_data = enrichir_via_nvd(cve_id)
        
        if result["cvss_score"] == "Non disponible" and nvd_data["cvss"]:
            result["cvss_score"] = nvd_data["cvss"]
            print("   -> CVSS recupere via NVD")
            
        if result["cwe"] == "Non disponible" and nvd_data["cwe"]:
            result["cwe"] = nvd_data["cwe"]
            print("   -> CWE recupere via NVD")

    # ---- 3. EPSS ----
    try:
        epss = session.get(EPSS_API + cve_id, timeout=10).json()
        result["epss_score"] = epss["data"][0]["epss"]
        print("FIRST (EPSS) OK")
    except:
        print("Aucun score EPSS trouve")
        
    return result

# ================== 4 ENRICHIR TOUTES LES CVE ==================

def enrichir_toutes_les_cve(flux_cve, cache, label, jours_rafraichissement=30):
    print(f"Enrichissement des CVE ({label})")
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
                        if delta.days >= jours_rafraichissement:
                            maj_necessaire = True
                if maj_necessaire:
                    print(f"{compteur}/{total} -- {cve_id}")
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

# ================== 5 EXTRACTION ID ANSSI & CISA ==================

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
        
        cisa_cves = {vuln['cveID'] for vuln in data['vulnerabilities']}
        print(f"[INFO] {len(cisa_cves)} vulnerabilites exploitees recensees par la CISA.")
        return cisa_cves
        
    except Exception as e:
        print(f"[ERREUR] Impossible de recuperer CISA KEV : {e}")
        return set()

# ================== 6 CONSTRUCTION DATAFRAME ==================

def add_rows(rows, flux, flux_cve, cache, type_bulletin, cisa_set=None):
    if cisa_set is None:
        cisa_set = set()

    print_step(f"Etape 4 -- Construction des lignes ({type_bulletin})")
    for titre, meta in flux.items():
        lien_anssi = meta.get("link", "")
        id_anssi = extraire_id_anssi_from_link(lien_anssi)

        for cve in flux_cve.get(titre, []):
            cache_entry = cache.get(cve, {})
            details = cache_entry.get("data", cache_entry) if "data" in cache_entry else cache_entry
            if not details: details = {}
            produits = details.get("products", [])
            if not produits:
                produits = [{"vendor": "Non disponible", "product": "Non disponible", "versions": []}]

            exploitation_active = "OUI" if cve in cisa_set else "Non"

            for p in produits:
                if not isinstance(p, dict):
                    vendor, produit, versions = "Non disponible", "Non disponible", []
                else:
                    vendor = p.get("vendor", "Non disponible")
                    produit = p.get("product") or p.get("product_name", "Non disponible")
                    versions = p.get("versions", [])

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
    print("\nTableau construit\n")

# ================= 7 DETECTION D'ALERTES ET ENVOI EMAIL ==================

def detecter_alertes(df):
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
        "Cordialement,\n"
        "Équipe Sécurité ESILV\n"
    )
    return message

def envoyer_email_brevo(liste_destinataires, sujet, message):
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(BREVO_SMTP_LOGIN, BREVO_API_KEY)
        print("Connexion SMTP etablie.")

        for destinataire in liste_destinataires:
            try:
                msg = MIMEText(message)
                msg["From"] = BREVO_SENDER_EMAIL
                msg["To"] = destinataire 
                msg["Subject"] = sujet

                server.sendmail(BREVO_SENDER_EMAIL, destinataire, msg.as_string())
                print(f" -> Email envoye avec succes a {destinataire}")
            except Exception as e_indiv:
                print(f" -> Erreur d'envoi pour {destinataire} : {e_indiv}")

        server.quit()
        print("Fermeture de la connexion SMTP.")
        return True
        
    except Exception as e:
        print(f"Echec global de la connexion Brevo : {e}")
        return False

# ================== 8 MAIN ==================

if __name__ == "__main__":

    print_step("DEBUT DU PIPELINE")
    
    if MODE_LOCAL == False:
        flux_alerte, flux_avis = recupFlux()
 
    flux_alerte = save_functions.charger_json_en_dict("flux_alerte.json")
    flux_avis = save_functions.charger_json_en_dict("flux_avis.json")

    set_cisa_kev = recuperer_cisa_kev()

    flux_alerte_cve = extraire_cves_depuis_flux(flux_alerte, "alerte")
    flux_avis_cve = extraire_cves_depuis_flux(flux_avis, "avis")
   
    cve_cache = save_functions.charger_json_en_dict("details_cve_anssi.json")

    enrichir_toutes_les_cve(flux_alerte_cve, cve_cache, "alerte")
    enrichir_toutes_les_cve(flux_avis_cve, cve_cache, "avis")

    rows = []
    add_rows(rows, flux_alerte, flux_alerte_cve, cve_cache, "Alerte", set_cisa_kev)
    add_rows(rows, flux_avis, flux_avis_cve, cve_cache, "Avis", set_cisa_kev)

    df = pd.DataFrame(rows)
    df.to_csv("anssi_cve_dataframe.csv", index=False)
    save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

    print_step("PIPELINE TERMINE")
    print("Nombre total de lignes :", df.shape[0])
    
    # ================= GESTION DES ALERTES (UNIQUEMENT LES NOUVELLES) =================

    print_step("ANALYSE DES ALERTES")
    
    # 1. Charger l'historique des alertes déjà envoyées
    # Format du dictionnaire : {"sent_ids": ["LienBulletin::CVE", ...]}
    history_data = save_functions.charger_json_en_dict(HISTORY_FILE)
    if history_data is None:
        history_data = {"sent_ids": []}
    
    sent_ids_set = set(history_data.get("sent_ids", []))
    
    # 2. Filtrer les vulnérabilités critiques
    df_alertes_all = detecter_alertes(df)
    
    nouvelles_alertes = []
    new_ids_to_add = []

    if not df_alertes_all.empty:
        for index, row in df_alertes_all.iterrows():
            # Création d'un ID unique : Lien Bulletin + ID CVE
            unique_id = f"{row['Lien du bulletin (ANSSI)']}::{row['Identifiant CVE']}"
            
            if unique_id not in sent_ids_set:
                nouvelles_alertes.append(row)
                new_ids_to_add.append(unique_id)

    # Convertir en DataFrame pour l'affichage/envoi
    df_nouvelles_alertes = pd.DataFrame(nouvelles_alertes)

    if not df_nouvelles_alertes.empty:
        print(f"{df_nouvelles_alertes.shape[0]} NOUVELLES vulnérabilités CRITIQUES détectées.")

        message = construire_message_alerte(df_nouvelles_alertes)
        
        if "REMPLACER" in BREVO_API_KEY:
            print("ERREUR : Vous avez oublie de coller votre CLE API en haut du script.")
        elif BREVO_SMTP_LOGIN and BREVO_SENDER_EMAIL and ALERT_MAILING_LIST:
            sujet = f"ALERTE SECURITE : {df_nouvelles_alertes.shape[0]} Nouvelles Failles Critiques"
            
            # Si l'envoi réussit, on met à jour l'historique
            if envoyer_email_brevo(ALERT_MAILING_LIST, sujet, message):
                # Mise à jour du set local
                sent_ids_set.update(new_ids_to_add)
                # Sauvegarde sur disque
                history_data["sent_ids"] = list(sent_ids_set)
                save_functions.sauvegarder_dict_en_json(history_data, HISTORY_FILE)
                print(f"Historique des alertes mis à jour dans {HISTORY_FILE}")
                
        else:
            print("Impossible d'envoyer l'email : Configuration incomplete ou liste vide.")

    else:
        print("Aucune NOUVELLE alerte critique depuis le dernier envoi.")
import feedparser
import requests
import re
import pandas as pd
import time
from datetime import datetime, timedelta
import save_functions
import smtplib
from email.mime.text import MIMEText

# ================== CONSTANTES CONFIGURATION ==================


BREVO_SMTP_LOGIN = "9fb516001@smtp-brevo.com"

BREVO_API_KEY = "xsmtpsib-49ead3b448981f859e516f2bc8b0c48ed7d9fbfa8ef31b438282c7029593dff4-KFGR3G3bkoUDWykg"

BREVO_SENDER_EMAIL = "projet.alertes.esilv@gmail.com"

ALERT_RECIPIENT = "m.diawarapro2005@gmail.com"



MODE_LOCAL = False
RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
CVE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587


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
        # Charger le cache existant
        flux_cache = save_functions.charger_json_en_dict(fichier_cache) or {}

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()
            rss = feedparser.parse(resp.text)
            nb = len(rss.entries)
            print(f"{nb} entrees trouvees dans {label}")

            maj = False
            for e in rss.entries:
                # Ajouter uniquement les nouveaux bulletins
                if e.title not in flux_cache:
                    flux_cache[e.title] = {
                        "description": e.description,
                        "link": e.link,
                        "published": e.published,
                        "json_content": None
                    }
                    maj = True
                    print(f"  Nouveau bulletin ajouté : {e.title}")
                    
                else:
                    # Vérifier si le bulletin existant a été mis à jour
                    cached_date = flux_cache[e.title].get("published")
                    if cached_date != e.published:
                        flux_cache[e.title].update({
                            "description": e.description,
                            "link": e.link,
                            "published": e.published,
                            "json_content": None  # reset pour forcer le re-téléchargement
                        })
                        maj = True
                        print(f"  Bulletin mis à jour : {e.title}")
            time.sleep(0.2)

            # Sauvegarde seulement si quelque chose a changé
            if maj:
                save_functions.sauvegarder_dict_en_json(flux_cache, fichier_cache)
                print(f"Flux {label} mis à jour dans {fichier_cache}")
            else:
                print(f" Pas de nouveauté pour {label}, cache inchangé")

            return flux_cache

        except Exception as e:
            print(f"Erreur lors du chargement de {label} : {e}")
            return flux_cache  # retourner le cache existant même en cas d'erreur

    rss_alertes = charger(RSS_ALERTES, "Alertes ANSSI", "flux_alerte.json")
    rss_avis = charger(RSS_AVIS, "Avis ANSSI", "flux_avis.json")

    print("\nRESUME DE L'ETAPE 1")
    print("----------------------------")
    print(f"{len(rss_alertes)} alertes recuperees")
    print(f"{len(rss_avis)} avis recuperes")

    return rss_alertes, rss_avis


# ================== 2 EXTRACTION DES CVE (utilisation directe du cache JSON) ==================


def extraire_cves_depuis_flux(flux, nom_flux):
    print_step(f" Étape 2 — Extraction des CVE depuis : {nom_flux}")

    resultat = {}
    total_cve = 0
    bulletin_count = len(flux)

    print(f" {bulletin_count} bulletins à analyser\n")

    with requests.Session() as s:
        index = 0
        for titre, meta in flux.items():
            index += 1
            print(f" Bulletin {index}/{bulletin_count} : {titre}")

            json_text = meta.get("json_content")
            cached_published = meta.get("cached_published")

            # Vérification si le JSON est absent ou le bulletin a été mis à jour
            if not json_text or cached_published != meta["published"]:
                try:
                    resp = s.get(meta["link"] + "json/", timeout=10)
                    resp.raise_for_status()
                    json_text = resp.text
                    # Mettre à jour le JSON et la date publiée dans le cache
                    meta["json_content"] = json_text
                    meta["cached_published"] = meta["published"]
                    save_functions.sauvegarder_dict_en_json(flux, f"flux_{nom_flux.lower()}.json")
                    print("    Bulletin téléchargé ou mis à jour")
                except Exception as e:
                    print(f"   Erreur : {e}")
                    json_text = ""
                time.sleep(2)
                    
            else:
                print("  Bulletin récupéré depuis le cache local")

            # Extraction des CVE
            cves = list(set(re.findall(CVE_PATTERN, json_text)))
            resultat[titre] = cves
            total_cve += len(cves)
            print(f"  {len(cves)} CVE trouvées")

            

    print(f"\nRÉSUMÉ ÉTAPE 2 — {nom_flux}")
    print("--------------------------------")
    print(f" CVE totales trouvées : {total_cve}")

    return resultat




# ================== 3 ENRICHISSEMENT CVE ==================

def enrichir_cve(cve_id, session):

    print(f"Recuperation details MITRE + FIRST pour {cve_id}")

    result = {
        "description": "Non disponible",
        "cvss_score": "Non disponible",
        "cwe": "Non disponible",
        "cwe_desc": "Non disponible",
        "products": [],
        "epss_score": "Non disponible"
    }

    # ---- MITRE ----
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
                "vendor": p.get("vendor"),
                "product": p.get("product"),
                "versions": [
                    v.get("version")
                    for v in p.get("versions", [])
                    if v.get("status") == "affected"
                ]
            })
        print("MITRE OK")

    except Exception as e:
        print(f"MITRE indisponible : {e}")
    
    time.sleep(0.2)

    # ---- EPSS ----
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
   
    try:
        cvss = float(cvss)
    except:
        cvss = None

    try:
        epss = float(epss)
    except:
        epss = None

    if cvss is None and epss is None:
        return "Non disponible"

    # Priorité au CVSS
    if cvss is not None:
        if cvss >= 9:
            return "Critique"
        elif cvss >= 7:
            return "Haute"
        elif cvss >= 4:
            return "Moyenne"
        else:
            return "Faible"
    
    # Si CVSS non dispo, on utilise EPSS
    if epss is not None:
        if epss >= 0.8:
            return "Critique"
        elif epss >= 0.5:
            return "Haute"
        elif epss >= 0.2:
            return "Moyenne"
        else:
            return "Faible"




# ================== 5 CONSTRUCTION DATAFRAME ==================

def add_rows(rows, flux, flux_cve, cache, type_bulletin):

    print_step(f"Etape 4 -- Construction des lignes ({type_bulletin})")

    bulletin_total = len(flux)
    compteur = 0

    for titre, meta in flux.items():
        compteur += 1

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

                rows.append({
                "Titre du bulletin (ANSSI)": titre,
                "Type de bulletin": type_bulletin,
                "Date de publication": meta.get("published"),
                "Identifiant CVE": cve,
                "Score CVSS": details.get("cvss_score"),
                "Type CWE": details.get("cwe"),
                "Score EPSS": details.get("epss_score"),
                "Lien du bulletin (ANSSI)": meta.get("link"),
                "Description": details.get("description"),
                "Editeur/Vendor": vendor,
                "Produit": produit,
                "Versions affectees": ", ".join(versions),
                "Severity": calculer_severity(details.get("cvss_score"), details.get("epss_score"))
                    })

    print("\nTableau construit\n")
    

# ================= 6 DETECTION D'ALERTES ET ENVOI EMAIL ==================

def detecter_alertes(df):
    # Criteres : CVSS >= 9, EPSS >= 0.8, et type "Alerte"
    return df[
        (pd.to_numeric(df["Score CVSS"], errors="coerce") >= 9) &
        (pd.to_numeric(df["Score EPSS"], errors="coerce") >= 0.8) &
        (df["Type de bulletin"] == "Alerte")
    ]


def construire_message_alerte(df_alertes):
    message = "ALERTE DE SECURITE -- Vulnerabilites critiques detectees \n\n"

    for _, row in df_alertes.iterrows():
        message += (
            f"CVE : {row['Identifiant CVE']}\n"
            f"Produit : {row['Produit']}\n"
            f"Editeur : {row['Editeur/Vendor']}\n"
            f"Score CVSS : {row['Score CVSS']}\n"
            f"Score EPSS : {row['Score EPSS']}\n"
            f"CWE : {row['Type CWE']}\n"
            f"Lien ANSSI : {row['Lien du bulletin (ANSSI)']}\n"
            "------------------------------------------\n"
        )

    return message


def envoyer_email_brevo(destinataire, sujet, message):
    """
    Envoie un email via l'API SMTP de Brevo.
    Utilise l'authentification separee du champ 'From'.
    """
    msg = MIMEText(message)
    
    # 1. 
    msg["From"] = BREVO_SENDER_EMAIL
    msg["To"] = destinataire
    msg["Subject"] = sujet

    try:
        # 2. CONNEXION TECHNIQUE 
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        
        server.login(BREVO_SMTP_LOGIN, BREVO_API_KEY)
        
        # 3. ENVOI
        server.sendmail(BREVO_SENDER_EMAIL, destinataire, msg.as_string())
        server.quit()
        print(f"Email envoye avec succes via Brevo a {destinataire}")
        
    except Exception as e:
        print(f"Echec de l'envoi via Brevo : {e}")


# ================== 7 MAIN ==================

if __name__ == "__main__":

    print_step("DEBUT DU PIPELINE")
    if MODE_LOCAL == False:
        flux_alerte, flux_avis = recupFlux()
     # Chargement
    flux_alerte = save_functions.charger_json_en_dict("flux_alerte.json")
    flux_avis = save_functions.charger_json_en_dict("flux_avis.json")

    flux_alerte_cve = extraire_cves_depuis_flux(flux_alerte, "alerte")
    flux_avis_cve = extraire_cves_depuis_flux(flux_avis, "avis")
   

    cve_cache = save_functions.charger_json_en_dict("details_cve_anssi.json")

    enrichir_toutes_les_cve(flux_alerte_cve, cve_cache, "alerte")
    enrichir_toutes_les_cve(flux_avis_cve, cve_cache, "avis")

    # Construction DataFrame
    rows = []
    add_rows(rows, flux_alerte, flux_alerte_cve, cve_cache, "Alerte")
    add_rows(rows, flux_avis, flux_avis_cve, cve_cache, "Avis")

    df = pd.DataFrame(rows)
    df.to_csv("anssi_cve_dataframe.csv", index=False)
    save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

    print_step("PIPELINE TERMINE")
    print("Nombre total de lignes :", df.shape[0])

    
    # # ================= GESTION DES ALERTES =================

    print_step("ANALYSE DES ALERTES")
    
    df_alertes = detecter_alertes(df)
    
    if not df_alertes.empty:
        print(f"{df_alertes.shape[0]} vulnerabilites CRITIQUES detectees.")

        # Construction du message
        message = construire_message_alerte(df_alertes)
        
        # Verification que les variables sont remplies
        if "REMPLACER" in BREVO_API_KEY:
            print("ERREUR : Vous avez oublie de coller votre CLE API en haut du script.")
        elif BREVO_SMTP_LOGIN and BREVO_SENDER_EMAIL and ALERT_RECIPIENT:
            sujet = f"ALERTE SECURITE : {df_alertes.shape[0]} Failles Critiques Detectees"
            envoyer_email_brevo(ALERT_RECIPIENT, sujet, message)
        else:
            print("Impossible d'envoyer l'email : Configuration incomplete.")

    else:
        print("Aucune alerte critique ne correspond aux criteres (CVSS >= 9 & EPSS >= 0.8).")
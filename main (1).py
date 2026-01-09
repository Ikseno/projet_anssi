import feedparser
import requests
import re
import pandas as pd
import time
import save_functions
import os
import smtplib
from email.mime.text import MIMEText


RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
CVE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


def print_step(titre):
    print("\n" + "="*70)
    print(titre)
    print("="*70)


# ================= 1️⃣ FLUX RSS ==================

def recupFlux():
    print_step("📥 Étape 1 — Récupération des flux RSS ANSSI")

    flux_alerte = {
        e.title: {
            "description": e.description,
            "link": e.link,
            "published": e.published
        }
        for e in feedparser.parse(RSS_ALERTES).entries
    }

    flux_avis = {
        e.title: {
            "description": e.description,
            "link": e.link,
            "published": e.published
        }
        for e in feedparser.parse(RSS_AVIS).entries
    }

    print(f"✔ {len(flux_alerte)} alertes récupérées")
    print(f"✔ {len(flux_avis)} avis récupérés")

    return flux_alerte, flux_avis


# ================= 2️⃣ EXTRACTION CVE ==================

def extraire_cves_depuis_flux(flux, nom_flux):
    print_step(f"🔎 Étape 2 — Extraction des CVE depuis : {nom_flux}")

    resultat = {}
    total_cve = 0

    with requests.Session() as s:
        for titre, meta in flux.items():
            try:
                resp = s.get(meta["link"] + "json/", timeout=10)
                resp.raise_for_status()

                cves = list(set(re.findall(CVE_PATTERN, resp.text)))
                resultat[titre] = cves
                total_cve += len(cves)

                print(f"• {titre} → {len(cves)} CVE trouvées")

            except Exception as e:
                print(f"⚠️ Erreur pour {titre}: {e}")
                resultat[titre] = []

            time.sleep(1)

    print(f"\n✔ Total CVE trouvées dans {nom_flux} : {total_cve}")
    return resultat


# ================= 3️⃣ ENRICHIR UNE CVE ==================

def enrichir_cve(cve_id, session):
    result = {
        "description": "Non disponible",
        "cvss_score": "Non disponible",
        "cwe": "Non disponible",
        "cwe_desc": "Non disponible",
        "products": [],
        "epss_score": "Non disponible"
    }

    try:
        data = session.get(CVE_API + cve_id, timeout=10).json()
        cna = data["containers"]["cna"]

        desc = cna.get("descriptions", [{}])[0]
        result["description"] = desc.get("value", "Non disponible")

        metrics = cna.get("metrics", [{}])[0]

        if "cvssV3_1" in metrics:
            result["cvss_score"] = metrics["cvssV3_1"].get("baseScore", "Non disponible")
        elif "cvssV3_0" in metrics:
            result["cvss_score"] = metrics["cvssV3_0"].get("baseScore", "Non disponible")

        pt = cna.get("problemTypes", [{}])[0].get("descriptions", [{}])[0]
        result["cwe"] = pt.get("cweId", "Non disponible")
        result["cwe_desc"] = pt.get("description", "Non disponible")

        for p in cna.get("affected", []):
            result["products"].append({
                "vendor": p.get("vendor", "Non disponible"),
                "product": p.get("product", "Non disponible"),
                "versions": [
                    v.get("version")
                    for v in p.get("versions", [])
                    if v.get("status") == "affected"
                ]
            })

    except Exception as e:
        print(f"⚠️ Erreur MITRE pour {cve_id}: {e}")

    try:
        epss = session.get(EPSS_API + cve_id, timeout=10).json()
        result["epss_score"] = epss["data"][0]["epss"]
    except:
        pass

    time.sleep(1)
    return result


# ================= 4️⃣ ENRICHIR TOUTES LES CVE ==================

def enrichir_toutes_les_cve(flux_cve, cache, label):
    print_step(f"🧠 Étape 3 — Enrichissement des CVE ({label}) via API")

    total = sum(len(v) for v in flux_cve.values())
    deja_cache = len(cache)

    print(f"✔ {total} CVE détectées")
    print(f"✔ {deja_cache} déjà présentes dans le cache")

    compteur = 0

    with requests.Session() as session:
        for cve_list in flux_cve.values():
            for cve_id in cve_list:

                if cve_id not in cache:
                    compteur += 1
                    print(f"→ Enrichissement {compteur} / {total} : {cve_id}")
                    cache[cve_id] = enrichir_cve(cve_id, session)

    print("\n✔ Enrichissement terminé.")


# ================= 5️⃣ DATAFRAME ==================

def add_rows(rows, flux, flux_cve, cache, type_bulletin):

    print_step(f"📊 Étape 4 — Construction des lignes ({type_bulletin})")

    for titre, meta in flux.items():
        for cve in flux_cve.get(titre, []):
            details = cache.get(cve, {})
            produits = details.get("products", [])

            if not produits:
                produits = [{
                    "vendor": "Non disponible",
                    "product": "Non disponible",
                    "versions": []
                }]

            for p in produits:
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
                    "Éditeur/Vendor": p.get("vendor"),
                    "Produit": p.get("product"),
                    "Versions affectées": ", ".join(p.get("versions", []))
                })


# ================= 6️⃣ DÉTECTION D'ALERTES ET ENVOI EMAIL ==================

def detecter_alertes(df):
    # Critères : CVSS >= 9, EPSS >= 0.8, et type "Alerte"
    return df[
        (pd.to_numeric(df["Score CVSS"], errors="coerce") >= 9) &
        (pd.to_numeric(df["Score EPSS"], errors="coerce") >= 0.8) &
        (df["Type de bulletin"] == "Alerte")
    ]


def construire_message_alerte(df_alertes):
    message = "ALERTE DE SÉCURITÉ – Vulnérabilités critiques détectées \n\n"

    for _, row in df_alertes.iterrows():
        message += (
            f"CVE : {row['Identifiant CVE']}\n"
            f"Produit : {row['Produit']}\n"
            f"Éditeur : {row['Éditeur/Vendor']}\n"
            f"Score CVSS : {row['Score CVSS']}\n"
            f"Score EPSS : {row['Score EPSS']}\n"
            f"CWE : {row['Type CWE']}\n"
            f"Lien ANSSI : {row['Lien du bulletin (ANSSI)']}\n"
            "------------------------------------------\n"
        )

    return message


def envoyer_email(expediteur, password, destinataire, sujet, message, smtp_server="smtp.gmail.com", smtp_port=587):
    msg = MIMEText(message)
    msg["From"] = expediteur
    msg["To"] = destinataire
    msg["Subject"] = sujet

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(expediteur, password)
    server.sendmail(expediteur, destinataire, msg.as_string())
    server.quit()


# ================= 7️⃣ MAIN ==================

if __name__ == "__main__":

    print_step("🚀 DÉBUT DU PIPELINE")

    flux_alerte = save_functions.charger_json_en_dict("flux_alerte.json")
    flux_avis = save_functions.charger_json_en_dict("flux_avis.json")

    flux_alerte_cve = extraire_cves_depuis_flux(flux_alerte, "Alertes ANSSI")
    flux_avis_cve = extraire_cves_depuis_flux(flux_avis, "Avis ANSSI")

    cve_cache = save_functions.charger_json_en_dict("details_cve_anssi.json")

    enrichir_toutes_les_cve(flux_alerte_cve, cve_cache, "Alertes")
    enrichir_toutes_les_cve(flux_avis_cve, cve_cache, "Avis")

    rows = []
    add_rows(rows, flux_alerte, flux_alerte_cve, cve_cache, "Alerte")
    # Si tu veux aussi ajouter les avis au DataFrame, décommente la ligne suivante :
    # add_rows(rows, flux_avis, flux_avis_cve, cve_cache, "Avis")

    df = pd.DataFrame(rows)

    df.to_csv("anssi_cve_dataframe.csv", index=False)
    save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

    print_step("✅ PIPELINE TERMINÉ")
    print("Nombre total de lignes :", df.shape[0])
    print(df.head())

    # Détection et envoi d'alertes
    df_alertes = detecter_alertes(df)
    if not df_alertes.empty:
        print_step("📣 ALERTES DÉTECTÉES")
        print(f"{df_alertes.shape[0]} vulnérabilités critiques correspondent aux critères.")

        message = construire_message_alerte(df_alertes)
        print("\nAperçu du message d'alerte :\n")
        print(message)

        # Récupération des paramètres d'envoi depuis les variables d'environnement
        sender = os.getenv("ALERT_EMAIL_SENDER")
        password = os.getenv("ALERT_EMAIL_PASSWORD")
        recipient = os.getenv("ALERT_EMAIL_RECIPIENT")
        smtp_server = os.getenv("ALERT_EMAIL_SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("ALERT_EMAIL_SMTP_PORT", 587))

        if sender and password and recipient:
            sujet = "ALERTE SECURITE - Vulnérabilités critiques ANSSI"
            try:
                envoyer_email(sender, password, recipient, sujet, message, smtp_server, smtp_port)
                print("✔ Email d'alerte envoyé à", recipient)
            except Exception as e:
                print("⚠️ Échec de l'envoi de l'email d'alerte :", e)
        else:
            print("ℹ️ Email non envoyé — configurez les variables d'environnement :")
            print("   ALERT_EMAIL_SENDER, ALERT_EMAIL_PASSWORD, ALERT_EMAIL_RECIPIENT")
    else:
        print("ℹ️ Aucune alerte critique détectée selon les critères.")
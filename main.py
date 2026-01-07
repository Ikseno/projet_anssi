import feedparser
import requests
import re
import pandas as pd
import time
import save_functions


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


# ================= 6️⃣ MAIN ==================

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
    

    df = pd.DataFrame(rows)

    df.to_csv("anssi_cve_dataframe.csv", index=False)
    save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

    print_step("✅ PIPELINE TERMINÉ")
    print("Nombre total de lignes :", df.shape[0])
    print(df.head())

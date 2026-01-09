import feedparser
import requests
import re
import pandas as pd
import time
from datetime import datetime, timedelta
import save_functions


# ================== CONSTANTES ==================

MODE_LOCAL=True 
RSS_ALERTES = "https://www.cert.ssi.gouv.fr/alerte/feed/"
RSS_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
CVE_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


# ================== AFFICHAGE ==================

def print_step(titre):
    print("\n" + "="*70)
    print(titre)
    print("="*70)


# ================== 1 RRS ==================

def recupFlux():
    print_step(">> Etape 1 -- Recuperation des flux RSS ANSSI (ONLINE)")

    headers = {"User-Agent": "Mozilla/5.0 (ESILV Student Project)"}

    def charger(url, label):
        print(f"\n>> Telechargement du flux : {label}")

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            resp.raise_for_status()

            rss = feedparser.parse(resp.text)

            nb = len(rss.entries)
            print(f"[OK] {nb} entrées trouvées dans {label}")

            return rss

        except Exception as e:
            print(f"[ERR] Erreur lors du chargement de {label} : {e}")
            return None
    

    rss_alertes = charger(RSS_ALERTES, "Alertes ANSSI")
    rss_avis = charger(RSS_AVIS, "Avis ANSSI")

    flux_alerte = {}
    flux_avis = {}

    if rss_alertes:
        flux_alerte = {
            e.title: {
                "description": e.description,
                "link": e.link,
                "published": e.published
            }
            for e in rss_alertes.entries
        }

    if rss_avis:
        flux_avis = {
            e.title: {
                "description": e.description,
                "link": e.link,
                "published": e.published
            }
            for e in rss_avis.entries
        }

    print("\n[i] RESUME DE L'ETAPE 1")
    print("----------------------------")
    print(f"+ {len(flux_alerte)} alertes récupérées")
    print(f"+ {len(flux_avis)} avis récupérés")

    return flux_alerte, flux_avis



# ================== 2 EXTRACTION CVE ==================

def extraire_cves_depuis_flux(flux, nom_flux):
    print_step(f"[?] Etape 2 -- Extraction des CVE (MODE LOCAL) : {nom_flux}")

    resultat = {}
    total_cve = 0
    bulletin_count = len(flux)

    print(f"[i] {bulletin_count} bulletins à analyser en mémoire\n")
    
    for titre, meta in flux.items():
        # On récupère les données locales
        # On scanne à la fois le Titre et la Description pour être sûr
        contenu_texte = str(titre) + " " + str(meta.get("description", ""))

        try:
            # On applique le regex directement sur le texte qu'on a déjà
            cves = list(set(re.findall(CVE_PATTERN, contenu_texte)))
            
            resultat[titre] = cves
            total_cve += len(cves)
            
            if cves:
                print(f">> {titre[:50]}... : {len(cves)} CVE trouvées")

        except Exception as e:
            print(f"   [ERR] Erreur lecture locale : {e}")
            resultat[titre] = []


    print(f"\n[i] RESUME ETAPE 2 -- {nom_flux}")
    print("--------------------------------")
    print(f"+ CVE totales trouvées : {total_cve}")

    return resultat



# ================== 3 ENRICHISSEMENT CVE ==================

def enrichir_cve(cve_id, session):

    print(f"   -> Récupération détails MITRE + FIRST pour {cve_id}")

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

        pt = cna.get("problemTypes", [{}])[0].get("descriptions", [{}])[0]
        result["cwe"] = pt.get("cweId")
        result["cwe_desc"] = pt.get("description")

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

        print("   [OK] MITRE OK")

    except Exception as e:
        print(f"   [ERR] MITRE indisponible : {e}")

    # ---- EPSS ----
    try:
        epss = session.get(EPSS_API + cve_id, timeout=10).json()
        result["epss_score"] = epss["data"][0]["epss"]
        print("   [OK] FIRST (EPSS) OK")

    except:
        print("   [!] Aucun score EPSS trouvé")

    time.sleep(1)

    return result



# ================== 4 ENRICHIR TOUTES ==================

def enrichir_toutes_les_cve(flux_cve, cache, label, jours_rafraichissement=30):
    print(f"[*] Enrichissement des CVE ({label})")

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
                    print(f">> {compteur}/{total} -- {cve_id}")
                    cache[cve_id] = {
                        "data": enrichir_cve(cve_id, session),
                        "last_update": time.strftime("%Y-%m-%d")
                    }
                    # sauvegarde progressive
                    save_functions.sauvegarder_dict_en_json(cache, "details_cve_anssi.json")



# ================== 5 CONSTRUCTION DATAFRAME ==================

def add_rows(rows, flux, flux_cve, cache, type_bulletin):

    print_step(f"[#] Etape 4 -- Construction des lignes ({type_bulletin})")

    bulletin_total = len(flux)
    compteur = 0

    for titre, meta in flux.items():
        compteur += 1
        print(f">> Bulletin {compteur}/{bulletin_total} : {titre}")

        for cve in flux_cve.get(titre, []):

            # Correction potentielle : on accède à la clé 'data' si elle existe
            cache_entry = cache.get(cve, {})
            details = cache_entry.get("data", cache_entry) if "data" in cache_entry else cache_entry
            
            # Si le cache est vide ou mal formé
            if not details: 
                details = {}

            produits = details.get("products", [])

            if not produits:
                produits = [{
                    "vendor": "Non disponible",
                    "product": "Non disponible",
                    "versions": []
                }]

            for p in produits:

                if not isinstance(p, dict):
                    vendor = "Non disponible"
                    produit = "Non disponible"
                    versions = []
                else:
                    vendor = p.get("vendor", "Non disponible")
                    produit = p.get("product", "Non disponible")
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
                    "Éditeur/Vendor": vendor,
                    "Produit": produit,
                    "Versions affectées": ", ".join(versions)
                })

    print("\n[OK] Tableau construit\n")
    



# ================== 6 MAIN ==================



if __name__ == "__main__":

    print_step(">>> DEBUT DU PIPELINE")
    if MODE_LOCAL==False:
        flux_alerte,flux_avis=recupFlux()
    
    # En mode local, on charge les fichiers existants
    flux_alerte = save_functions.charger_json_en_dict("flux_alerte.json")
    flux_avis = save_functions.charger_json_en_dict("flux_avis.json")


    flux_alerte_cve = extraire_cves_depuis_flux(flux_alerte, "Alertes ANSSI")
    flux_avis_cve = extraire_cves_depuis_flux(flux_avis, "Avis ANSSI")

    cve_cache = save_functions.charger_json_en_dict("details_cve_anssi.json")

    enrichir_toutes_les_cve(flux_alerte_cve, cve_cache, "Alertes")
    enrichir_toutes_les_cve(flux_avis_cve, cve_cache, "Avis")

    rows = []
    add_rows(rows, flux_alerte, flux_alerte_cve, cve_cache, "Alerte")
    add_rows(rows, flux_avis, flux_avis_cve, cve_cache, "Avis")

    df = pd.DataFrame(rows)

    df.to_csv("anssi_cve_dataframe.csv", index=False)
    save_functions.sauvegarder_dict_en_json(cve_cache, "details_cve_anssi.json")

    print_step("[OK] PIPELINE TERMINE")
    print("Nombre total de lignes :", df.shape[0])
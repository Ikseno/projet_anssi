import feedparser 
import requests 
import re 
import pandas as pd
import save_functions


# ================================== Fonctions ==================================

def recupFlux():
    url_alerte,url_avis = "https://www.cert.ssi.gouv.fr/alerte/feed/" ,"https://www.cert.ssi.gouv.fr/avis/feed/" 
    rss_feed_alerte,rss_feed_avis = feedparser.parse(url_alerte) , feedparser.parse(url_avis)
    flux_alerte={entry.title:{"description":entry.description,"link":entry.link,"published":entry.published} for entry in rss_feed_alerte.entries}
    flux_avis={entry.title:{"description":entry.description,"link":entry.link,"published":entry.published} for entry in rss_feed_avis.entries}
    return flux_alerte, flux_avis

def recupCveFlux(flux_alerte, flux_avis):
    flux_alerte_cve,flux_avis_cve={},{}
    for title in flux_alerte.keys():
        url = str(flux_alerte[title]["link"]) + "json/" 
        response = requests.get(url) 
        data = response.json() 
        # Extraction des CVE avec une regex 
        cve_pattern = r"CVE-\d{4}-\d{4,7}" 
        cve_list = list(set(re.findall(cve_pattern, str(data)))) 
        
        flux_alerte_cve[title]=cve_list
    
    for title in flux_avis.keys():
        url = str(flux_avis[title]["link"]) + "json/" 
        response = requests.get(url) 
        data = response.json() 
        # Extraction des CVE avec une regex 
        cve_pattern = r"CVE-\d{4}-\d{4,7}" 
        cve_list = list(set(re.findall(cve_pattern, str(data)))) 

        flux_avis_cve[title]=cve_list
    
    return flux_alerte_cve, flux_avis_cve
    

def enrichissement_cve_alerte(flux_alerte_cve, dictionnaire_cve_details):
    for cve_list in flux_alerte_cve.values():
        for cve_id in cve_list:
            if not cve_id in dictionnaire_cve_details:
                url = f"https://cveawg.mitre.org/api/cve/{cve_id}" 
                response = requests.get(url) 
                data = response.json()
                try:
                    # Extraire la description  
                    description = data["containers"]["cna"]["descriptions"][0]["value"]  
                except (KeyError, IndexError):  
                    description = "Non disponible"
                # Extraire le score CVSS  
                #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,  
                #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé 
                try:
                    cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
                except KeyError:
                    try:
                        cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
                    except KeyError:
                        cvss_score = "Non disponible"
                cwe = "Non disponible" 
                cwe_desc="Non disponible" 
                problemtype = data["containers"]["cna"].get("problemTypes", {}) 
                if problemtype and "descriptions" in problemtype[0]: 
                    cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible") 
                    cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible") 
            
                # Extraire les produits affectés
                try:
                    affected = data["containers"]["cna"]["affected"] 
                except KeyError:
                    affected = []
                if affected != []:
                    products = []
                    for product in affected: 
                        vendor = product.get("vendor", "Non disponible")
                        product_name = product.get("product", "Non disponible")
                        try:
                            versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                        except KeyError:
                            versions = ["Non disponible"]
                        products.append({"vendor": vendor, "product_name": product_name, "versions": versions})
                else:
                    products = ["Non disponible"]
                
                url_epss= f"https://api.first.org/data/v1/epss?cve={cve_id}" 
                # Requête GET pour récupérer les données JSON 
                response_epss= requests.get(url_epss) 
                data_epss= response_epss.json() 
                # Extraire le score EPSS 
                epss_data = data_epss.get("data", []) 
                epss_score="non disponible"
                if epss_data: 
                    epss_score = epss_data[0].get("epss","non disponible") 
                    
                    # Afficher les résultats  
                dictionnaire_cve_details[cve_id]={"description":description,"cvss_score":cvss_score,"cwe":cwe,"cwe_desc":cwe_desc,
                                                "products":products,"epss_score":epss_score
                                                }


# marche pas pour l'instant (car dépasse sûrement le nombre de requêtes autorisées par l'API en un temps donné)
def enrichissement_cve_avis(flux_avis_cve, dictionnaire_cve_details):
    for cve_list in flux_avis_cve.values():
        for cve_id in cve_list:
            if not cve_id in dictionnaire_cve_details:
                url = f"https://cveawg.mitre.org/api/cve/{cve_id}" 
                response = requests.get(url) 
                data = response.json()
                try:
                    # Extraire la description  
                    description = data["containers"]["cna"]["descriptions"][0]["value"]  
                except (KeyError, IndexError):  
                    description = "Non disponible"
                # Extraire le score CVSS  
                #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,  
                #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé 
                try:
                    cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_0"]["baseScore"]
                except KeyError:
                    try:
                        cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
                    except KeyError:
                        cvss_score = "Non disponible"
                cwe = "Non disponible" 
                cwe_desc="Non disponible" 
                try:
                    problemtype = data["containers"]["cna"].get("problemTypes", {}) 
                except KeyError:
                    problemtype = {}
                if problemtype and "descriptions" in problemtype[0]: 
                    cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible") 
                    cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible") 
            
                # Extraire les produits affectés
                try:
                    affected = data["containers"]["cna"]["affected"] 
                except KeyError:
                    affected = []
                if affected != []:
                    products = []
                    for product in affected: 
                        vendor = product.get("vendor", "Non disponible")
                        product_name = product.get("product", "Non disponible")
                        try:
                            versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                        except KeyError:
                            versions = ["Non disponible"]
                        products.append({"vendor": vendor, "product_name": product_name, "versions": versions})
                else:
                    products = ["Non disponible"]
                
                url_epss= f"https://api.first.org/data/v1/epss?cve={cve_id}" 
                # Requête GET pour récupérer les données JSON 
                response_epss= requests.get(url_epss) 
                data_epss= response_epss.json() 
                # Extraire le score EPSS 
                epss_data = data_epss.get("data", []) 
                epss_score="non disponible"
                if epss_data: 
                    epss_score = epss_data[0].get("epss","non disponible") 
                    
                    # Afficher les résultats  
                dictionnaire_cve_details[cve_id]={"description":description,"cvss_score":cvss_score,"cwe":cwe,"cwe_desc":cwe_desc,
                                                "products":products,"epss_score":epss_score
                                                }



def add_rows_from_flux(rows, flux, flux_cve, bulletin_type):
    for title, meta in flux.items():
        cve_list = flux_cve.get(title, [])
        for cve_id in cve_list:
            details = dictionnaire_cve_details.get(cve_id, {})

            # Produits (peut être une liste)
            products = details.get("products", ["Non disponible"])

            if isinstance(products, list) and products and isinstance(products[0], dict):
                for p in products:
                    rows.append({
                        "Titre du bulletin (ANSSI)": title,
                        "Type de bulletin": bulletin_type,
                        "Date de publication": meta.get("published"),
                        "Identifiant CVE": cve_id,
                        "Score CVSS": details.get("cvss_score"),
                        "Type CWE": details.get("cwe"),
                        "Score EPSS": details.get("epss_score"),
                        "Lien du bulletin (ANSSI)": meta.get("link"),
                        "Description": details.get("description"),
                        "Éditeur/Vendor": p.get("vendor"),
                        "Produit": p.get("product_name"),
                        "Versions affectées": ", ".join(p.get("versions", []))
                    })
            else:
                rows.append({
                    "Titre du bulletin (ANSSI)": title,
                    "Type de bulletin": bulletin_type,
                    "Date de publication": meta.get("published"),
                    "Identifiant CVE": cve_id,
                    "Score CVSS": details.get("cvss_score"),
                    "Type CWE": details.get("cwe"),
                    "Score EPSS": details.get("epss_score"),
                    "Lien du bulletin (ANSSI)": meta.get("link"),
                    "Description": details.get("description"),
                    "Éditeur/Vendor": "Non disponible",
                    "Produit": "Non disponible",
                    "Versions affectées": "Non disponible"
                })

# ====================================================================

if __name__ == '__main__':
    flux_alerte, flux_avis = save_functions.charger_json_en_dict("flux_alerte.json"), save_functions.charger_json_en_dict("flux_avis.json")
    flux_alerte_cve, flux_avis_cve = recupCveFlux(flux_alerte, flux_avis)
    dictionnaire_cve_details = save_functions.charger_json_en_dict("details_cve_anssi.json")

    rows = []
    # Ajout des alertes et avis
    add_rows_from_flux(rows, flux_alerte, flux_alerte_cve, "Alerte")

    # Création du DataFrame
    df = pd.DataFrame(rows)

    print(df.head())
    print(df.columns)
    print(df.shape)

    df.to_csv("anssi_cve_dataframe.csv", index=False)
    deff=[]
    

    
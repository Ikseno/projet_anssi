import feedparser 
import requests 
import re 
import pandas as pd

url_alerte,url_avis = "https://www.cert.ssi.gouv.fr/alerte/feed/" ,"https://www.cert.ssi.gouv.fr/avis/feed/" 

rss_feed_alerte,rss_feed_avis = feedparser.parse(url_alerte) , feedparser.parse(url_avis)

flux_alerte={entry.title:{"description":entry.description,"link":entry.link,"published":entry.published} for entry in rss_feed_alerte.entries}
flux_avis={entry.title:{"description":entry.description,"link":entry.link,"published":entry.published} for entry in rss_feed_avis.entries}


flux_alerte_cve,flux_avis_cve={},{}
for title in flux_alerte.keys():
    url = str(flux_alerte[title]["link"]) + "json/" 
    response = requests.get(url) 
    data = response.json() 
    #Extraction des CVE reference dans la clé cves du dict data 
    ref_cves=list(data["cves"])  
    # Extraction des CVE avec une regex 
    cve_pattern = r"CVE-\d{4}-\d{4,7}" 
    cve_list = list(set(re.findall(cve_pattern, str(data)))) 
    
    flux_alerte_cve[title]=cve_list

for title in flux_avis.keys():
    url = str(flux_avis[title]["link"]) + "json/" 
    response = requests.get(url) 
    data = response.json() 
    #Extraction des CVE reference dans la clé cves du dict data 
    ref_cves=list(data["cves"])  
    # Extraction des CVE avec une regex 
    cve_pattern = r"CVE-\d{4}-\d{4,7}" 
    cve_list = list(set(re.findall(cve_pattern, str(data)))) 

    flux_avis_cve[title]=cve_list

dictionnaire_cve_details={}

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

            # Afficher les résultats  
            dictionnaire_cve_details[cve_id]={"description":description,"cvss_score":cvss_score,"cwe":cwe,"cwe_desc":cwe_desc,
                                               "products":products
                                               }

print(dictionnaire_cve_details)
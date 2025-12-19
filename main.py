import feedparser 
import requests 
import re 

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
    
print(flux_avis_cve)
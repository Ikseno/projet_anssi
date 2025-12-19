import feedparser 

url = "https://www.cert.ssi.gouv.fr/feed/" 
rss_feed = feedparser.parse(url) 
flux_rss={}
for entry in rss_feed.entries: 
    flux_rss[entry.title]={"description":entry.description,"link":entry.link,"published":entry.published}
    
print(flux_rss)
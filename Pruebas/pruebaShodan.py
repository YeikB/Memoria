from shodan import Shodan
from shodan.cli.helpers import get_api_key
import csv
import time
import json

api = Shodan(get_api_key())

limit = 30000
counter = 0
i=0
data =[]
for banner in api.search_cursor('city:Concepción country:cl'):
    # Perform some custom manipulations or stream the results to a database
    # For this example, I'll just print out the "data" property
    data.append(banner)

    # Keep track of how many results have been downloaded so we don't use up all our query credits
    counter += 1
    if counter >= limit:
        break
print(len(data))


hosts= []
i = 1
for ip in data:
	print(ip['ip_str'], " ", i)
	try:
		hosts.append(api.host(ip['ip_str']))
		time.sleep(1.5)
	except:
		print("tuvimos un error, ojopiojo")
	i=i+1

with open('Conce.json', 'w') as fout:
    json.dump(hosts, fout)

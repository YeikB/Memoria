import networkx as nx
import json
from ares import CVESearch
from cvss import CVSS3
import pandas as pd
import time
cve = CVESearch()
orgs = {}

with open(r"Stgo445.json", "r") as read_file:
    data = json.load(read_file)
print(len(data))
with open(r"cvesV2.json", "r") as read_file:
    cves= json.load(read_file)
print("Largo cves inicial",len(cves))
for i,dato in enumerate(data):
    #agrego informacion de las vulnerabilidades
    vuls = []
    if dato.get('vulns'):
        for x in dato.get('vulns'):
            if x in cves:
                vuls.append(cves[x])
            else:
                try:
                    cveid =cve.id(x)
                    vuls.append(cveid)
                    cves[x] =cveid
                    print("Se agrego una nueva vuln: ",x,", van: ",len(cves))
                    time.sleep(1)
                except:
                    print("hubo un problema, nos saltamos una vuln")
    else:
        dato['vulns'] = []

with open('cvesV3.json', 'w') as fout:
    json.dump(cves, fout)
import networkx as nx
import json
from ares import CVESearch
from cvss import CVSS3
import pandas as pd

cve = CVESearch()
orgs = {}

with open(r"445Conce.json", "r") as read_file:
    data = json.load(read_file)
#genero un diccionario de Sistemas operativos obsoletos.
OSobsoletos = {
    "2008 R2":1,
    "2008":2,
    "2003":3,
    "xp":4,
    "2000":5,
    "Linux 3.1":6
}
#genero diccionario de puertos
df = pd.read_csv('Puertos.csv',sep=';')
dictPuertos= df.set_index('Puertos').T.to_dict('list')
#leo de diccionario de vulnerabilidades especifica para este dataset para que sea mas rapido.
with open(r"cves.json", "r") as read_file:
    cves= json.load(read_file)

#diccionario de organizaciones
orgs = {}
#esta parte se puede hacer al principio del modelo, de esta forma se podria cambiar el criterio de agrupacion, para que no sea solo de org.
#se mantiene en esta parte por temas de velocidad ya que esta parte solo se llama una vez, mientras que el modelo se llama al menos dos veces.

for i,dato in enumerate(data):
    #agrego informacion de las vulnerabilidades
    vuls = []
    if dato.get('vulns'):
        for x in dato.get('vulns'):
            if x in cves:
                vuls.append(cves[x])
            else:
                cveid =cve.id(x)
                vuls.append(cveid)
                cves[x] =cveid
    else:
        dato['vulns'] = []

    dato['CVE'] = vuls
    #agrego informacion sobre la obsolecencia de el sistema operativo, solo un valor, entre mas alto peor
    for k in OSobsoletos.keys():
        dato['ObsSO']=0
        if not dato.get('os'):
             dato['ObsSO']= -1
        if dato.get('os') and k in dato['os'] :
            dato['ObsSO'] = OSobsoletos[k]
            break

    #hago un diccionario con las organizaciones a las que pertenece cada resultado en data 
    if dato['org'] in orgs:
        orgs[dato['org']]= orgs[dato['org']] + [i]
    else:
        orgs[dato['org']] = [i]

print(data[25]['CVE'][0]['access']['complexity'])
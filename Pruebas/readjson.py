import networkx as nx
import json
from ares import CVESearch
import pandas as pd

cve = CVESearch()
orgs = {}


with open(r"445Conce.json", "r") as read_file:
    data = json.load(read_file)
with open(r"cves.json", "r") as read_file:
    cves= json.load(read_file)

df = pd.read_csv('Puertos.csv',sep=';')
dictPuertos= df.set_index('Puertos').T.to_dict('list')
print(dictPuertos[443]) 

for dato in data:
	scorePuertos = 0
	contador = 0
	if dato.get('ports'):
		for x in dato['ports']:
			if dictPuertos.get(x) and dictPuertos[x][1] >0:
				scorePuertos += dictPuertos[x][1]
				contador +=1
	dato['scorePuertos'] = scorePuertos / contador

nodo = 14
print(data[nodo]['ports'])
print(data[nodo]['scorePuertos'])
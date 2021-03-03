import networkx as nx
import json
from ares import CVESearch
import pandas as pd

cve = CVESearch()
orgs = {}


with open(r"445Conce.json", "r") as read_file:
    data = json.load(read_file)

#diccionario de organizaciones
orgs = {}
#esta parte se puede hacer al principio del modelo, de esta forma se podria cambiar el criterio de agrupacion, para que no sea solo de org.
#se mantiene en esta parte por temas de velocidad ya que esta parte solo se llama una vez, mientras que el modelo se llama al menos dos veces.

for i,dato in enumerate(data):
	if dato['org'] in orgs:
	    orgs[dato['org']]= orgs[dato['org']] + [i]
	else:
	    orgs[dato['org']] = [i]

DatosxOrg = []
for o in orgs.keys():
    orgTemp = []    
    for ag in orgs[o]:
        orgTemp.append(data[ag])
    nodoCentral = {"org":orgTemp[0]['org']}
    orgTemp.append(nodoCentral)
    DatosxOrg.append(orgTemp)
print(DatosxOrg[0][7])
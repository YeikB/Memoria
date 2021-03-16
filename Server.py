import math
import json
import pandas as pd

from mesa.visualization.ModularVisualization import ModularServer
from mesa.visualization.UserParam import UserSettableParameter
from mesa.visualization.modules import ChartModule
from mesa.visualization.modules import NetworkModule
from mesa.visualization.modules import TextElement


from Model import VirusOnNetwork, State, number_COMPROMETIDO

from shodan import Shodan
from shodan.cli.helpers import get_api_key
from ares import CVESearch
cve = CVESearch()
#api = Shodan(get_api_key())

with open(r"Stgo445.json", "r") as read_file:
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
with open(r"cvesV3.json", "r") as read_file:
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

    #se genera una evaluacion de los puertos abiertos, de acuerdo a la criticidad indicada en el diccionario
    #Si hay mas de 1 puerto de maxima criticidad se tendra valor critico de 10 que es el mas alto
    #si no, se usa la ponderacion de los puertos abiertos, como esta puntuacion es de 1 a 5, se multiplicara por 2 
    contador1 = 0
    contador2 = 0
    suma_puertos = 0
    if dato.get('ports'):
        for x in dato['ports']:
            if dictPuertos.get(x):
                if dictPuertos[x][1] == 5:
                    contador2 += 1
                suma_puertos += dictPuertos[x][1]     
                
            else:
                suma_puertos += 0
            contador1 += 1
        if contador2 > 1:
            suma_puertos  = 10
        elif contador1 > 0:
            suma_puertos = round( (suma_puertos * 2) / contador1 )
    else:
        dato['ports'] = []
        suma_puertos = 1

    dato['punt_puertos'] = suma_puertos 

    #se define una puntuacion de acuerdo a la peor de las cvss de todas las vulnerabilidades
    if(len(dato['CVE'])>0):
            punt_vuln = 0
            contador = 0
            for v in dato['CVE']:
                if v is not None:
                    punt_vuln += v['cvss']
                    contador += 1
            try:
                dato['punt_vuln'] =  round (punt_vuln / contador, 2) 
            except:
                dato['punt_vuln'] = 0
    else:
        dato['punt_vuln'] = 0

    #se define una puntuacion de cultura organizacional del nodo, de 1 a 10 donde 10 es la peor puntuacion
  
    if dato['ObsSO'] > 0:
        dato['punt_SO'] = 10
    else:
        dato['punt_SO'] = 1

    puntaje = dato['punt_vuln'] + dato['punt_puertos'] + dato['punt_SO']
    puntaje = round((puntaje / 3),2)

    dato['punt_nodo'] = puntaje
    if puntaje < 5:
        dato['Nivel'] = "Bueno"
    elif puntaje >= 5 and puntaje <7:
        dato['Nivel'] = "Medio"
    elif puntaje <9 :
        dato['Nivel'] = "Grave"
    else:
        dato['Nivel'] = "Critico"

def sort_by_puntaje(dato):
    return dato['punt_nodo']

Empresas = list(orgs.keys())
for i,e in enumerate(Empresas):
    if type(e) != str:
        break
orgs.pop(e)
Empresas = list(orgs.keys())
Empresas.sort()
print(len(Empresas))
DatosxOrg = []
for o in orgs.keys():
    orgTemp = []    
    for ag in orgs[o]:
        orgTemp.append(data[ag])
    nodoCentral = {"org":orgTemp[0]['org']}
    orgTemp.sort(reverse = True, key = sort_by_puntaje)
    orgTemp.insert(0,nodoCentral)
    DatosxOrg.append(orgTemp)


 
def network_portrayal(G):

    def node_color(agent):
        if agent.tipo == "Nodo":
            if agent.estado == State.SUSCEPTIBLE:
                if agent.Nivel == "Bueno":
                    return "#13a600"
                elif agent.Nivel == "Medio":
                    return "#d7e300"
                elif agent.Nivel == "Grave":
                    return "#ed0f00" 
                else:
                    return "#7d0b5b"
            elif agent.estado == State.EN_ATAQUE:
                return "#d8f0de"
            elif agent.estado == State.COMPROMETIDO:
                return "#000000"
            elif agent.estado == State.ATACADO:
                return "#9da1ed"
            else:
                return "#23a83c"

        elif agent.tipo == "Central":
            return "#1c2694"
        else:
            return "#acaebf"    

    def edge_color(agent1, agent2):
        if agent2.tipo == "Nodo":
            if agent2.estado == State.SUSCEPTIBLE:
                if agent2.Nivel == "Bueno":
                    return "#13a600"
                elif agent2.Nivel == "Medio":
                    return "#d7e300"
                elif agent2.Nivel == "Grave":
                    return "#ed0f00" 
                else:
                    return "#7d0b5b"
            elif agent2.estado == State.EN_ATAQUE:
                return "#d8f0de"
            elif agent2.estado == State.COMPROMETIDO:
                return "#000000"
            elif agent2.estado == State.ATACADO:
                return "#9da1ed"
            else:
                return "#23a83c"
        return "#000000"

    def edge_width(agent1, agent2):
        if agent1.tipo == "Central" and agent2.tipo == "Nodo":   
            return 0.5
        else:
            return 0.1  

    def node_info(agent):
        if agent.tipo == "Nodo":
            info = "ip: {}<br>puntaje nodo: {}<br>vuln: {}<br>Puertos: {}<br>SO: {}".format(
                    agent.ip, agent.punt_nodo,agent.punt_vuln, agent.punt_puertos,agent.punt_SO
                )
        elif agent.tipo == "Central":
            info = "{}<br>cultura: {}".format(
                    agent.org, agent.cultura_Organizacional
                )
        else:
             info = "Org: {}<br>".format(
                    agent.org
                )
        return info
    def size_nodes(agent):
        if agent.tipo == "Nodo":
            return 4
        elif agent.tipo == "Central":
            return 6
        else:
            return 2    

    def get_agents(source, target):
        return G.nodes[source]["agent"][0], G.nodes[target]["agent"][0]

    def node_label(agent):
        if agent.tipo =="Central":
            return "{}".format(agent.org)
        else:
            return None 

    portrayal = dict()
    portrayal["nodes"] = [
        {
            "size": size_nodes(agents[0]) ,
            "color": node_color(agents[0]),
            "tooltip":node_info(agents[0]) ,
            "label": node_label(agents[0]),
          
        }
        for (_, agents) in G.nodes.data("agent")
    ]

    portrayal["edges"] = [
        {
            "source": source,
            "target": target,
            "color": edge_color(*get_agents(source, target)),
            "width": edge_width(*get_agents(source, target)),
        }
        for (source, target) in G.edges
    ]

    return portrayal


network = NetworkModule(network_portrayal, 400, 500, library="d3")
chart = ChartModule(
    [
        {"Label": "Comprometido", "Color": "#FF0000"},
        {"Label": "Susceptible", "Color": "#008000"},
        {"Label": "Atacado", "Color": "#808080"},
    ]
)

class MyTextElement(TextElement):
    def render(self, model):
        ratio = model.atacado_susceptible_ratio()
        ratio_text = "&infin;" if ratio is math.inf else "{0:.2f}".format(ratio)
        COMPROMETIDO_text = str(number_COMPROMETIDO(model))

        return "{}<br>{}<br>{}<br>{}<br>{}".format(
            model.mensaje0, model.mensaje1,model.mensaje2, model.mensaje3,model.mensaje4
        )


model_params = {
    "lista":DatosxOrg,
    "detener": UserSettableParameter("checkbox", "Detener en primer objetivo", False),
    "single": UserSettableParameter("checkbox", "Solo Organización objetivo", False),
    "experticie_atacante": UserSettableParameter(
        "slider",
        "Nivel de experticie atacante",
        1,
        1,
        3,
        1,
        description="Escoja el nivel de experticie que tendrá el atacante.",
    ),
    "motivacion": UserSettableParameter(
        "slider",
        "Nivel de Motivacion",
        5,
        1,
        10,
        0.1,
        description="Escoja el nivel de experticie que tendrá el atacante.",
    ),
    "objetivo": UserSettableParameter(
        "choice",
        "Organizacion objetivo",
        value=Empresas[147],
        choices=Empresas,
    ),
}

server = ModularServer(
    VirusOnNetwork, [network, MyTextElement()], "Modelo Simulación Escenario Ciberseguridad", model_params
)
server.port = 8521

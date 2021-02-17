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

with open(r"445Conce.json", "r") as read_file:
    data = json.load(read_file)
#genero un diccionario de Sistemas operativos obsoletos.
OSobsoletos = {
    "2008 R2":1,
    "2008":2,
    "2003":3,
    "xp":4,
    "2000":5
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

    dato['CVE'] = vuls
    #agrego informacion sobre la obsolecencia de el sistema operativo, solo un valor, entre mas alto peor
    for k in OSobsoletos.keys():
        dato['ObsSO']=0
        if dato.get('os') and k in dato['os'] :
            dato['ObsSO'] = OSobsoletos[k]
            break

    #hago un diccionario con las organizaciones a las que pertenece cada resultado en data 
    if dato['org'] in orgs:
        orgs[dato['org']]= orgs[dato['org']] + [i]
    else:
        orgs[dato['org']] = [i]

    #agrego un valor relacionado a los puertos abiertos que tenia el resultado
    port_Score = 0
    contador = 0
    if dato.get('ports'):
        for x in dato['ports']:
            if dictPuertos.get(x) and dictPuertos[x][1] > 0:
                port_Score += dictPuertos[x][1]
                contador +=1
    else:
        dato['ports'] = []

    dato['port_Score'] = port_Score / contador


DatosxOrg = []
for o in orgs.keys():
    orgTemp = []    
    for ag in orgs[o]:
        orgTemp.append(data[ag])
    nodoCentral = {"org":orgTemp[0]['org']}
    orgTemp.insert(0,nodoCentral)
    DatosxOrg.append(orgTemp)

 
def network_portrayal(G):

    def node_color(agent):
        return {State.COMPROMETIDO: "#FF0000", State.SUSCEPTIBLE: "#008000"}.get(
          agent.state, "#808080"
    )

    def edge_color(agent1, agent2):
        if State.RESISTANT in (agent1.state, agent2.state):
            return "#000000"
        return "#000000"

    def edge_width(agent1, agent2):
        if State.RESISTANT in (agent1.state, agent2.state):
            return 1
        return 0.5
    def node_info(agent):
        if agent.tipo == "Nodo":
            info = "Org: {}<br>ip: {}<br>cvss: {}<br>port_Score: {}".format(
                    agent.org, agent.ip,agent.vuln_Score, agent.port_Score
                )
        else:
            info = "Org: {}<br>cultura: {}".format(
                    agent.org, agent.cultura_Organizacional
                ) 
        return info

    def get_agents(source, target):
        return G.nodes[source]["agent"][0], G.nodes[target]["agent"][0]

    portrayal = dict()
    portrayal["nodes"] = [
        {
            "size": 4,
            "color": node_color(agents[0]),
            "tooltip":node_info(agents[0]) ,
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


network = NetworkModule(network_portrayal, 500, 500, library="d3")
chart = ChartModule(
    [
        {"Label": "COMPROMETIDO", "Color": "#FF0000"},
        {"Label": "Susceptible", "Color": "#008000"},
        {"Label": "Resistant", "Color": "#808080"},
    ]
)


class MyTextElement(TextElement):
    def render(self, model):
        ratio = model.resistant_susceptible_ratio()
        ratio_text = "&infin;" if ratio is math.inf else "{0:.2f}".format(ratio)
        COMPROMETIDO_text = str(number_COMPROMETIDO(model))

        return "Resistant/Susceptible Ratio: {}<br>COMPROMETIDO Remaining: {}".format(
            ratio_text, COMPROMETIDO_text
        )


model_params = {
    "lista":DatosxOrg,
    "experticie_atacante": UserSettableParameter(
        "slider",
        "Nivel de experticie atacante",
        1,
        1,
        3,
        1,
        description="Escoja el nivel de experticie que tendrá el atacante.",
    ),
}

server = ModularServer(
    VirusOnNetwork, [network, MyTextElement(), chart], "Modelo Simulacion Escenario Ciberseguridad", model_params
)
server.port = 8521

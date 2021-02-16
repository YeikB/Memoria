import math
import json

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
with open(r"445Conce.json", "r") as read_file:
    data = json.load(read_file)

#leo de diccionario de vulnerabilidades especifica para este dataset para que sea mas rapido.
with open(r"cves.json", "r") as read_file:
    cves= json.load(read_file)

#agrego informacion de las vulnerabilidades
for dato in data:
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

#api = Shodan(get_api_key())
orgs = {}

#diccionario de organizaciones
#esta parte se puede hacer al principio del modelo, de esta forma se podria cambiar el criterio de agrupacion, para que no sea solo de org.
#se mantiene en esta parte por temas de velocidad ya que esta parte solo se llama una vez, mientras que el modelo se llama al menos dos veces.
for i,a in enumerate(data):
  if a['org'] in orgs:
    orgs[a['org']]= orgs[a['org']] + [i]
  else:
    orgs[a['org']] = [i]

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

    def get_agents(source, target):
        return G.nodes[source]["agent"][0], G.nodes[target]["agent"][0]

    portrayal = dict()
    portrayal["nodes"] = [
        {
            "size": 4,
            "color": node_color(agents[0]),
            "tooltip": "ip: {}<br>Org: {}".format(
                agents[0].ip, agents[0].org
            ),
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

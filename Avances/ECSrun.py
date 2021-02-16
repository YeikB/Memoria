from ECSModel import *
import json
from shodan import Shodan
from shodan.cli.helpers import get_api_key
from mesa.visualization.modules import CanvasGrid
from mesa.visualization.ModularVisualization import ModularServer
data = [json.loads(line) for line in open('intento.json', 'r')]

api = Shodan(get_api_key())
dic = {}
print(data[0]['org'])
for i,a in enumerate(data):
	if a['org'] in dic:
		dic[a['org']]= dic[a['org']] + [i]
	else:
		dic[a['org']] = [i]
print(dic.values())

"""
def agent_portrayal(agent):
    portrayal = {"Shape": "circle",
                 "Filled": "true",
                 "Layer": agent.unique_id,
                 "Color": "red",
                 "r": 0.5}
    return portrayal

grid = CanvasGrid(agent_portrayal, 10, 10, 500, 500)
server = ModularServer(ECSModel,
                       [grid],
                       "ECS Model",
                       {"N":50, "width":10, "height":10,"lista":data})
server.port = 8521 # The default
server.launch()
"""
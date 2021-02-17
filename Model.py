import math
from enum import Enum
import networkx as nx

from mesa import Agent, Model
from mesa.time import RandomActivation
from mesa.datacollection import DataCollector
from mesa.space import NetworkGrid


class State(Enum):
    SUSCEPTIBLE = 0
    COMPROMETIDO = 1
    RESISTANT = 2


def number_state(model, state):  #Indica la cantidad de nodos por estado, puede ser util
    print
    return sum([1 for a in model.grid.get_all_cell_contents() if a.state is state])


def number_COMPROMETIDO(model):
    return number_state(model, State.COMPROMETIDO)


def number_susceptible(model):
    return number_state(model, State.SUSCEPTIBLE)


def number_resistant(model):
    return number_state(model, State.RESISTANT)


class VirusOnNetwork(Model):
    """A virus model with some number of agents"""

    def __init__(
        self,
        lista = [],
        experticie_atacante = 0, #representa un nivel de experticie, 1 = bajo, 2 = medio, 3 = alto. Quizas se haga con mas niveles.
    ):
        self.G = nx.empty_graph(0)

        correlative_num = 0
        central = 0
        for i,x in enumerate(lista):
            for j,y in enumerate(lista[i]):
                if j > 0:
                    self.G.add_node(correlative_num)
                    self.G.add_edge(correlative_num, central)
                else:
                    self.G.add_node(correlative_num)
                    central=correlative_num
                correlative_num+=1
            
        self.experticie_atacante = experticie_atacante

        self.grid = NetworkGrid(self.G)
        self.schedule = RandomActivation(self)

        self.datacollector = DataCollector(
            {
                "COMPROMETIDO": number_COMPROMETIDO,
                "Susceptible": number_susceptible,
                "Resistant": number_resistant,
            }
        )
        #creando a los agentes.
        correlative_num = 0
        central = 0
        for i,x in enumerate(lista):
            for j,info in enumerate(lista[i]):
                if j > 0:
                    a = VirusAgent(
                        correlative_num,
                        self,
                        State.SUSCEPTIBLE,
                        self.experticie_atacante,
                        info,
                        "Nodo"
                    )
                else:    
                    a = VirusAgent(
                        correlative_num,
                        self,
                        State.SUSCEPTIBLE,
                        self.experticie_atacante,
                        info,
                        "Central"
                    )
                    central = correlative_num
                self.schedule.add(a)
                # Add the agent to the node
                self.grid.place_agent(a, correlative_num)
                correlative_num+=1 

        self.running = True
        self.datacollector.collect(self)

    def resistant_susceptible_ratio(self):
        try:
            return number_state(self, State.RESISTANT) / number_state(
                self, State.SUSCEPTIBLE
            )
        except ZeroDivisionError:
            return math.inf

    def step(self):
        self.schedule.step()
        # collect data
        self.datacollector.collect(self)

    def run_model(self, n):
        for i in range(n):
            self.step()


class VirusAgent(Agent):
    def __init__(
        self,
        unique_id,
        model,
        initial_state,
        experticie_atacante,
        info,
        tipo,
    ):
        super().__init__(unique_id, model)
        self.info = info
       
        def puntuacion_vulns(self):
            vuln_Score = 0
            contador = 0
            for v in self.info['CVE']:
                if v is not None:
                    vuln_Score += v['cvss']
                    contador +=1
            self.vuln_Score = round(vuln_Score / contador,2)
             
        self.state = initial_state
        self.experticie_atacante = experticie_atacante
        self.tipo = tipo
        self.org = self.info['org']


        if  self.tipo == "Central":
            self.cultura_Organizacional = 0

        else:
            self.ip = info['ip_str']
            if(len(self.info['CVE'])>0):
                puntuacion_vulns(self)
            else:
                self.vuln_Score = 0
            
            if(len(self.info['ports'])):
                self.port_Score = self.info['port_Score']
            else:
                self.port_Score = 0
        

    def step(self):
        neighbors_nodes = self.model.grid.get_neighbors(self.pos, include_center=False)
        susceptible_neighbors = [
            agent
            for agent in self.model.grid.get_cell_list_contents(neighbors_nodes)
            if agent.tipo == "Central"
        ]
        for a in susceptible_neighbors:
            print("Dato de:"+self.org+self.ip+"hacia mi jefecito: "+a.org+a.ip)
    


    def calificar_cultura(self):
        print("Aqui vamos a calificar_cultura en caso de ser recurso le va a mandar un valor al nodo central, en caso de nodo central va a calcular cositas.")

""" la dejo porque es la misma estructura que para cuando sea atacado un nodo y quiera ver si se puede atacar otro.
  
    def try_to_infect_neighbors(self): 
        neighbors_nodes = self.model.grid.get_neighbors(self.pos, include_center=False)
        susceptible_neighbors = [
            agent
            for agent in self.model.grid.get_cell_list_contents(neighbors_nodes)
            if agent.state is State.SUSCEPTIBLE
        ]
        for a in susceptible_neighbors:
            if self.random.random() < self.virus_spread_chance:
                a.state = State.COMPROMETIDO


esta tambien la dejo porque puede ser un concepto interesante, aunque quizas impracticable

    def try_remove_infection(self):
        # Try to remove
        if self.random.random() < self.recovery_chance:
            # Success
            self.state = State.SUSCEPTIBLE
            self.try_gain_resistance()
        else:
            # Failed
            self.state = State.COMPROMETIDO
"""


    

import math
from enum import Enum
import networkx as nx

from mesa import Agent, Model
from mesa.time import BaseScheduler
from mesa.datacollection import DataCollector
from mesa.space import NetworkGrid
from random import randrange

class State(Enum):
    SUSCEPTIBLE = 0
    COMPROMETIDO = 1
    ATACADO = 2


def number_state(model, state):  #Indica la cantidad de nodos por estado, puede ser util
    return sum([1 for a in model.grid.get_all_cell_contents() if a.state is state])


def number_COMPROMETIDO(model):
    return number_state(model, State.COMPROMETIDO)


def number_susceptible(model):
    return number_state(model, State.SUSCEPTIBLE)


def number_atacado(model):
    return number_state(model, State.ATACADO)


class VirusOnNetwork(Model):
    """A virus model with some number of agents"""

    def __init__(
        self,
        lista = [],
        experticie_atacante = 0, #representa un nivel de experticie, 1 = bajo, 2 = medio, 3 = alto. Quizas se haga con mas niveles.
    ):
        self.objetivo = 0
        #randrange(len(lista))
        print(lista[self.objetivo][0]['org'])
        self.G = nx.empty_graph(0)
        #lo que tengo que hacer es que en el primer mierda, reconozca el ultimo de la lista, que sera el central, hacemos que en el primer elemento de la
        #lista cree el nodo central con el valor que deberia tener sumando 
        correlative_num = 0
        central = 0
        for i in range(len(lista)):
            for j,y in enumerate(lista[i]):
                if j > 0:
                    self.G.add_node(correlative_num, pos = (0,0))
                    self.G.add_edge(correlative_num, central)
                else:
                    self.G.add_node(correlative_num, pos = (0,0))
                    central=correlative_num
                y['correlativo'] = correlative_num 
                correlative_num+=1
        self.experticie_atacante = experticie_atacante

        self.grid = NetworkGrid(self.G)
        self.schedule = BaseScheduler(self)

        self.datacollector = DataCollector(
            {
                "COMPROMETIDO": number_COMPROMETIDO,
                "Susceptible": number_susceptible,
                "Resistant": number_atacado,
            }
        )
        #creando a los agentes.
        for i in range(len(lista)):
            for j,info in enumerate(reversed(lista[i])):
                if j < len(lista[i]) - 1 :
                    if info['ObsSO'] == -1 and len(info['ports'])==0 and len(info['vulns'])==0 :
                        a = VirusAgent(
                            info['correlativo'] ,
                            self,
                            State.SUSCEPTIBLE,
                            self.experticie_atacante,
                            self.objetivo,
                            info,
                            "dispositivo_com"
                        )
                    else:   
                        a = VirusAgent(
                            info['correlativo'],
                            self,
                            State.SUSCEPTIBLE,
                            self.experticie_atacante,
                            self.objetivo,
                            info,
                            "Nodo"
                        )

                else:    
                    a = VirusAgent(
                        info['correlativo'],
                        self,
                        State.SUSCEPTIBLE,
                        self.experticie_atacante,
                        self.objetivo,
                        info,
                        "Central"
                    )
                self.schedule.add(a)
                # Add the agent to the node
                self.grid.place_agent(a, info['correlativo'])

        self.running = True
        self.datacollector.collect(self)

    def atacado_susceptible_ratio(self):
        try:
            return number_state(self, State.ATACADO) / number_state(
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
        objetivo,
        info,
        tipo,
    ):
        super().__init__(unique_id, model)
        self.info = info


        
        def cultura_organizacional(self, puntuacion):
            print(self.cultura_Organizacional,"  ",puntuacion)

        def puntuacion_vulns(self):
            vuln_Score = 0
            contador = 0
            for v in self.info['CVE']:
                if v is not None:
                    vuln_Score += v['cvss']
                    contador +=1
            self.vuln_Score =  round(vuln_Score / contador,2)

        #se define una puntuacion en base al tiempo que tienen descubiertas parches para las vulnerabilidades.         
        def puntuacion_parches(self):
            for cve in self.info['CVE']:
                mayor_tiempo = 0
                if cve is not None:
                    descubierto = cve['id'].split("-") 
                    parche = cve['last-modified'].split("-")  
                    tiempo = int(parche[0]) - int(descubierto[1])
                    if tiempo > mayor_tiempo:
                        mayor_tiempo = tiempo
            if mayor_tiempo > 4:
                self.puntuacion_parches =  5
            else:
                self.puntuacion_parches =  mayor_tiempo

        #se define una puntuacion de cultura organizacional del nodo, de 1 a 10 donde 1 es la peor puntuacion
        def cultura_Organizacional_nodo(self):
            score = 5
            if self.info['ObsSO'] > 0 or self.info['port_Score'] == 6 or self.puntuacion_parches == 5:
                score = 1
                #no debo olvidar el tema de las fechas de las vulnerabilidades
            else:
                if len(self.info['ports']) > 2 or len(self.info['vulns']) > 3:
                    score -=1
                else:
                    score +=1

                if self.puntuacion_parches > 1:
                    score -=1
                else: 
                    score +=1 

                if self.info['port_Score'] > 4:
                    score -=1
                else:
                    score +=1

                if self.vuln_Score > 5:
                     score -=1
                else:
                    score +=1
                
            self.cultura_nodo = score

        self.state = initial_state
        self.experticie_atacante = experticie_atacante
        self.tipo = tipo
        self.org = self.info['org']
        self.objetivo = objetivo

        if  self.tipo == "Central":
            self.cultura_Organizacional = 0

        elif self.tipo == "Nodo":
            self.cultura = 0
            self.vul = len(self.info['CVE'])
            self.por = len(self.info['ports'])
            self.ip = info['ip_str']
            if(len(self.info['CVE'])>0):
                puntuacion_parches(self)
                puntuacion_vulns(self)
            else:
                self.vuln_Score = 0
                self.puntuacion_parches = 0
            
            if(len(self.info['ports'])):
                self.port_Score = self.info['port_Score']
            else:
                self.port_Score = 0
            cultura_Organizacional_nodo(self)
        else:
            self.ip = info['ip_str']
        self.first = True

    def cultura_nodos(self, cantidad):
        nodos_vecinos = self.model.grid.get_neighbors(self.pos, include_center=False)
        central = [
            agent
            for agent in self.model.grid.get_cell_list_contents(nodos_vecinos)
            if agent.tipo == "Central"
        ]
        central[0].cultura_Organizacional += cantidad

    def promedio_cultura(self):
        nodos_vecinos = self.model.grid.get_neighbors(self.pos, include_center=False)
        nodos = [
            agent
            for agent in self.model.grid.get_cell_list_contents(nodos_vecinos)
            if agent.tipo == "Nodo"
        ]
        self.cultura_Organizacional = round(self.cultura_Organizacional / len(nodos),1) 
        for n in nodos:
            n.cultura = self.cultura_Organizacional

    def nodo_mas_debil(self,nodo):
        print("Aqui vamos a retornar el nodo mas debil, si es necesario de acuerdo a otra wea")

    def step(self):
        if self.first:
            self.first = False
            if self.tipo =="Nodo":
                self.cultura_nodos(self.cultura_nodo)
            elif self.tipo == "Central":
                self.promedio_cultura()





   
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


    

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
    EN_ATAQUE = 3


def number_state(model, state):  #Indica la cantidad de nodos por estado, puede ser util
    return sum([1 for a in model.grid.get_all_cell_contents() if a.estado is state])


def number_COMPROMETIDO(model):
    return number_state(model, State.COMPROMETIDO)


def number_susceptible(model):
    return number_state(model, State.SUSCEPTIBLE)


def number_atacado(model):
    return number_state(model, State.ATACADO)

def number_en_ataque(model):
    return number_state(model,State.EN_ATAQUE)


class VirusOnNetwork(Model):
    """A virus model with some number of agents"""

    def __init__(
        self,
        lista = [],
        experticie_atacante = 0, #representa un nivel de experticie, 1 = bajo, 2 = medio, 3 = alto. Quizas se haga con mas niveles.
        motivacion = 5,
        objetivo = " ",
    ):

        self.objetivo = objetivo
        #randrange(len(lista))
        self.G = nx.empty_graph(0) 
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
        estado_inicial,
        experticie_atacante,
        objetivo,
        info,
        tipo,
    ):
        super().__init__(unique_id, model)
        self.info = info
        self.estado = estado_inicial
        self.experticie_atacante = experticie_atacante
        self.tipo = tipo
        self.org = self.info['org']

        #en caso de ser un nodo central maneja muchos menos variables
        if  self.tipo == "Central":
            self.cultura_Organizacional = 0
            self.objetivo = objetivo

        elif self.tipo == "Nodo":
            self.cultura = 0
            self.punt_puertos = self.info['punt_puertos']
            self.ip = info['ip_str']
            self.cantidad_vulns = len(self.info['vulns'])
            
            self.puntuacion_vulns()

            self.puntuacion_nodo()

        else:
            self.ip = info['ip_str']
        
        self.first = True

    #se define una puntuacion de acuerdo a la peor de las cvss de todas las vulnerabilidades
    def puntuacion_vulns(self):
        if(len(self.info['CVE'])>0):
            punt_vuln = 0
            contador = 0
            for v in self.info['CVE']:
                if v is not None:
                    punt_vuln += v['cvss']
                    contador += 1
            self.punt_vuln =  round (punt_vuln / contador, 2) 
        else:
            self.punt_vuln = 0

    #se define una puntuacion de cultura organizacional del nodo, de 1 a 10 donde 10 es la peor puntuacion
    def puntuacion_nodo(self):
            if self.info['ObsSO'] > 0:
                self.punt_SO = 10
            else:
                self.punt_SO = 5

            puntaje = self.punt_vuln + self.punt_puertos + self.punt_SO
            puntaje = round((puntaje / 3),2)

            self.punt_nodo = puntaje
            if puntaje < 5:
                self.Nivel = "Bueno"
            elif puntaje >= 5 and puntaje <7.5:
                self.Nivel = "Medio"
            else:
                self.Nivel = "Grave"

    #cada nodo entrega su puntuacion local al nodo central
    def entrega_punt_nodos(self, cantidad):
        nodos_vecinos = self.model.grid.get_neighbors(self.pos, include_center=False)
        central = [
            agent
            for agent in self.model.grid.get_cell_list_contents(nodos_vecinos)
            if agent.tipo == "Central"
        ]
        central[0].cultura_Organizacional += cantidad

    #se calcula un promedio de la puntuacion de cada nodo para obtener una punt de cultura organizacinal
    def promedio_cultura(self):
        nodos_vecinos = self.model.grid.get_neighbors(self.pos, include_center=False)
        agentes = [
            agent
            for agent in self.model.grid.get_cell_list_contents(nodos_vecinos)
            if agent.tipo == "Nodo"
        ]
        self.cultura_Organizacional = round(self.cultura_Organizacional / len(agentes),1) 
        for n in agentes:
            n.cultura = self.cultura_Organizacional
############################################################### hasta aqui funciona todo perfect #######################################################


    #funciones que facilitan ordenar listas en determinados momentos
    def sort_per_punt_nodo(self,agent):
        return agent.punt_nodo
    def sort_per_cvss(self,agent):
        peor_cvss = 0
        for v in agent.info['CVE']:
            if v is not None:
                if v['access']['complexity'] == "LOW":
                        temp = 1
                elif v['access']['complexity'] == "MEDIUM":
                    temp = 2
                else:
                    temp = 3
                if v['cvss']>peor_cvss and temp <= self.experticie_atacante:
                    peor_cvss = v['cvss']
        return peor_cvss


    def nodo_mas_debil(self,nodo_atacado= None):
        nodos_vecinos = self.model.grid.get_neighbors(self.pos, include_center=False)
        nodos_vulns = [
            agent
            for agent in self.model.grid.get_cell_list_contents(nodos_vecinos)
            if agent.tipo == "Nodo" and agent.cantidad_vulns > 0 and agent.estado == State.SUSCEPTIBLE
        ]
        #de esta lista de nodos_vulns, tengo que ver todos los que tienen vulnerabilidades con complejidades iguales o menores que la capacidad del atacante.
        nodos_atacables = []
        for n in nodos_vulns:
            for v in n.info['CVE']:
                if v is not None:
                    if v['access']['complexity'] == "LOW":
                        temp = 1
                    elif v['access']['complexity'] == "MEDIUM":
                        temp = 2
                    else:
                        temp = 3
                    if temp <= self.experticie_atacante:
                        nodos_atacables.append(n)
                        break
        #de esta lista de nodos ordenarlos de acuerdo a su cvss mas alto en una vulnerabilidad atacable segun capacidad del atacante
        nodos_atacables.sort(reverse=True, key=self.sort_per_cvss)
        print(len(nodos_atacables))
        """for n in nodos_atacables:
                                    for v in n.info['CVE']:
                                        print("cvss: ",v['cvss'],"complejidad: ",v['access']['complexity'], "UI: ", v['access']['authentication'])
                                    print("este fue el nodo: ",n.ip)"""
        ########################################aqui tengo que descartar los que tengan vuln con cvss menores a los que indique la motivacion
        if len(nodos_atacables) > 0:
            nodos_atacables[0].estado = State.EN_ATAQUE
            nodos_atacables.pop(0)
        else:
            print("hacer algo para que vaya a atacar a otra parte")
    
    def sort_by_cvss_cve(self,cve):
        return cve['cvss']

    def ataque_nodo(self):
        #tengo que encontrar la peor vulnerabilidad dentro de las capacidades del atacante, y de haber mas de una elegir una que no necesite UI
        vuls = []
        peor_cvss = 0
        for v in self.info['CVE']:
            if v is not None:
                    if v['access']['complexity'] == "LOW":
                        temp = 1
                    elif v['access']['complexity'] == "MEDIUM":
                        temp = 2
                    else:
                        temp = 3
                    if temp <= self.experticie_atacante:
                        vuls.append(v)
        vuls.sort(reverse = True,key=self.sort_by_cvss_cve)
        peor_vuln = vuls[0]
        for v in vuls:
            if v['cvss'] == peor_vuln['cvss'] and v['access']['authentication'] == "NONE":
                peor_vuln = v
                break
        if peor_vuln['access']['authentication'] == "NONE":
            self.estado = State.COMPROMETIDO
        else:
            print("Cultura organizacional: ",self.cultura_Organizacional)
            prob_error_humano = self.cultura_Organizacional * 10 
            if randrange(1,101) <= prob_error_humano:
                self.estado = State.COMPROMETIDO
            else:
                self.estado = State.ATACADO


    #De la organizacion objetivo se ven todas las vulnerabilidades de todos sus nodos, se eligen las que sean de la capacidad del atacante
    #de estas se eligen todas hasta (10 - el nivel de motivacion ) y se van eligiendo los nodos al que pertenezcan las vulnerabilidades en orden
    #del cvss de forma decreciente
    #cambien de objetivo 
    def step(self):
        if self.first:
            self.first = False
            if self.tipo =="Nodo":
                self.entrega_punt_nodos(self.punt_nodo)
            elif self.tipo == "Central":
                self.promedio_cultura()
        if self.estado == State.EN_ATAQUE:
            self.ataque_nodo()
            #ataque_nodo tiene que retornar algo en caso que comprometa al nodo atacado para darlo como argumento para encontrar nodo mas debil
        if self.tipo == "Central" and self.org == self.objetivo:
            self.nodo_mas_debil()


   
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


    

import math
from enum import Enum
import networkx as nx

from mesa import Agent, Model
from mesa.time import BaseScheduler
from mesa.datacollection import DataCollector
from mesa.space import NetworkGrid
from random import randrange,random

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
        detener = False,
        single = False,
    ):
        self.detener = detener
        self.motivacion = motivacion
        self.objetivo = objetivo
        self.mensaje0 = "Objetivo Actual: " + objetivo
        self.mensaje1 = ""
        self.mensaje2 = ""
        self.mensaje3 = ""
        self.mensaje4 = ""
        self.nodos_atacables = 1
        self.contador_nodos_atacados = 0
        self.contador_nodos_comprometidos = 0
        self.contador_nodos_no_comprometidos = 0
        
        self.G = nx.empty_graph(0) 
        correlative_num = 0
        central = 0
        for i,org in enumerate(lista):
            if org[0]['org'] == self.objetivo:
                self.num_org_obj=i
        if single:
            for j,y in enumerate(lista[self.num_org_obj]):
                if j > 0:
                    self.G.add_node(correlative_num)
                    self.G.add_edge(correlative_num, central)
                else:
                    self.G.add_node(correlative_num)
                    """if correlative_num > 0:
                                                                                      self.G.add_edge(correlative_num, central) """  
                    central=correlative_num
                y['correlativo'] = correlative_num 
                correlative_num+=1
        else:
            for i in range(len(lista)):
                for j,y in enumerate(lista[i]):
                    if j > 0:
                        self.G.add_node(correlative_num)
                        self.G.add_edge(correlative_num, central)
                    else:
                        self.G.add_node(correlative_num)
                        """if correlative_num > 0:
                                                                                          self.G.add_edge(correlative_num, central) """  
                        central=correlative_num
                    y['correlativo'] = correlative_num 
                    correlative_num+=1
        self.experticie_atacante = experticie_atacante
        self.nodos_centrales = []

        self.grid = NetworkGrid(self.G)
        self.schedule = BaseScheduler(self)

        self.datacollector = DataCollector(
            {
                "COMPROMETIDO": number_COMPROMETIDO,
                "Susceptible": number_susceptible,
                "Resistant": number_atacado,
            }
        )
        if single:
            for j,info in enumerate(reversed(lista[self.num_org_obj])):
                    if j < len(lista[self.num_org_obj]) - 1 :
                        if info['ObsSO'] == -1 and len(info['ports'])==0 and len(info['vulns'])==0 :
                            a = VirusAgent(
                                info['correlativo'] ,
                                self,
                                State.SUSCEPTIBLE,
                                self.experticie_atacante,
                                self.motivacion,
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
                                self.motivacion,
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
                            self.motivacion,
                            self.objetivo,
                            info,
                            "Central"
                        )
                        self.nodos_centrales.append(a)
                    self.schedule.add(a)
                    # Add the agent to the node
                    self.grid.place_agent(a, info['correlativo'])

        else:

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
                                self.motivacion,
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
                                self.motivacion,
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
                            self.motivacion,
                            self.objetivo,
                            info,
                            "Central"
                        )
                        self.nodos_centrales.append(a)
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
        if self.nodos_atacables == 0 and self.detener:
            self.running = False

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
        motivacion,
        objetivo,
        info,
        tipo,
    ):
        super().__init__(unique_id, model)
        self.info = info
        self.estado = estado_inicial
        self.experticie_atacante = experticie_atacante
        self.motivacion = 10 - motivacion
        self.tipo = tipo
        self.org = self.info['org']
        self.cultura_Organizacional = 0

        #en caso de ser un nodo central maneja muchos menos variables
        if  self.tipo == "Central":
            self.objetivo = objetivo
            self.atacado = False

        elif self.tipo == "Nodo":
            self.punt_puertos = self.info['punt_puertos']
            self.ip = info['ip_str']
            self.cantidad_vulns = len(self.info['vulns'])   
            
            self.punt_vuln = self.info['punt_vuln']
            self.punt_nodo = self.info['punt_nodo']
            self.Nivel = self.info['Nivel']
            self.punt_SO = self.info['punt_SO']

        else:
            self.ip = info['ip_str']
        
        self.first = True


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
            n.cultura_Organizacional = self.cultura_Organizacional

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
        nodos_vecinos = self.model.grid.get_neighbors(self.unique_id, include_center=False)
        nodos_vulns = [
            agent
            for agent in self.model.grid.get_cell_list_contents(nodos_vecinos)
            if agent.tipo == "Nodo" and agent.cantidad_vulns > 0 and agent.estado == State.SUSCEPTIBLE
        ]
        #de esta lista de nodos_vulns, tengo que ver todos los que tienen vulnerabilidades con complejidades iguales o menores que la capacidad del atacante.
        #y con un cvss que sea mayor que el limite impuesto por la motivacion
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
                    if temp <= self.experticie_atacante and self.motivacion <= v['cvss']:
                        nodos_atacables.append(n)
                        break
        #de esta lista de nodos ordenarlos de acuerdo a su cvss mas alto en una vulnerabilidad atacable segun capacidad del atacante
        nodos_atacables.sort(reverse=True, key=self.sort_per_cvss)
      
        print("Nodos atacables en este objetivo: ",len(nodos_atacables))
        """for n in nodos_atacables:
                                    for v in n.info['CVE']:
                                        print("cvss: ",v['cvss'],"complejidad: ",v['access']['complexity'], "UI: ", v['access']['authentication'])
                                    print("este fue el nodo: ",n.ip)"""
        ########################################aqui tengo que descartar los que tengan vuln con cvss menores a los que indique la motivacion

        if len(nodos_atacables) > 0:    
            nodos_atacables[0].estado = State.EN_ATAQUE
            if not self.atacado:
                self.model.mensaje2= "Recurso mas débil: " + nodos_atacables[0].ip+"&nbsp;&nbsp;&nbsp;&nbsp;Puntuación: " + str(nodos_atacables[0].punt_nodo)   
                self.model.mensaje3= ""
                self.model.mensaje4= ""
                self.atacado = True
            else:
                self.model.mensaje4= "Siguiente recurso mas débil: " + nodos_atacables[0].ip +"&nbsp;&nbsp;&nbsp;&nbsp;Puntuación: " + str(nodos_atacables[0].punt_nodo)
            self.model.mensaje0= "Objetivo Actual: " + self.objetivo        
            self.model.mensaje1= "Recursos atacables en este objetivo: " +str(len(nodos_atacables))
            self.model.nodos_atacables = len(nodos_atacables)
            nodos_atacables.pop(0)
        else:   
            #Se elige un nuevo nodo objetivo
            self.model.nodos_centrales = list(filter(lambda x: x.org !=self.objetivo,self.model.nodos_centrales))
            if len(self.model.nodos_centrales) > 0:
                nuevo_objetivo = randrange(len(self.model.nodos_centrales))
                nuevo_objetivo = self.model.nodos_centrales[nuevo_objetivo].org
                print("Se acabaron los objetivos aqui, me viro para aca: ",nuevo_objetivo)
                for central in self.model.nodos_centrales:
                    central.objetivo = nuevo_objetivo
                self.model.objetivo = nuevo_objetivo
                self.objetivo = nuevo_objetivo
                if self.model.detener:
                    self.model.mensaje4= "Simulación Terminada con éxito"
                else:    
                    self.model.mensaje4= "Como todos los objetivos han sido atacados, me muevo a atacar: " + nuevo_objetivo 
            else:
                #Caso en el que no hay mas objetivos disponibles
                """
                print("Se han acabado todos los objetivos")
                self.model.mensaje0= "Todas las organizaciones han sido atacadas"
                self.model.mensaje1= ""
                self.model.mensaje2= ""
                self.model.mensaje3= ""
                self.model.mensaje4= ""
                """
    def sort_by_cvss_cve(self,cve):
        return cve['cvss']

    def ataque_nodo(self):
        #tengo que encontrar la peor vulnerabilidad dentro de las capacidades del atacante, y de haber mas de una elegir una que no necesite UI
        vuls = []
        peor_cvss = 0
        for v in self.info['CVE']:  #Se sacan las vulnerabilidades que no estan al nivel del atacante o mas bajas de su motivacion
            if v is not None:
                    if v['access']['complexity'] == "LOW":
                        temp = 1
                    elif v['access']['complexity'] == "MEDIUM":
                        temp = 2
                    else:
                        temp = 3
                    if temp <= self.experticie_atacante and self.motivacion <= v['cvss']:
                        vuls.append(v)
        vuls.sort(reverse = True,key=self.sort_by_cvss_cve)
        peor_vuln = vuls[0]

        for v in vuls:  #Se busca entre las peores vulns una que no necesite error humano
            if v['cvss'] == peor_vuln['cvss'] and v['access']['authentication'] == "NONE":
                peor_vuln = v
                break
        if peor_vuln['access']['authentication'] == "NONE":
            self.model.mensaje2= "Recurso: " + self.ip + "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Puntuación recurso: " + str(self.punt_nodo) + "<br>Puntuación de Vulns: "+ str(self.punt_vuln)+"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Puntuación de SO: " +str(self.punt_SO)+"<br>Puntuación de Puertos: "+str(self.punt_puertos)+"&nbsp;&nbsp;&nbsp;&nbsp;Cult. Org.: " +str(self.cultura_Organizacional)+"<br>Este recurso presenta una vulnerabilidad que no necesita acción de usuario" 
            self.estado = State.COMPROMETIDO
            print("Nodo ",self.ip," Comprometido!")
            self.model.mensaje3="El recurso fue comprometido!"
        else:   
            print("Cultura organizacional: ",self.cultura_Organizacional)
            prob_error_humano = self.cultura_Organizacional * 10
            self.model.mensaje2= "Recurso: " + self.ip + "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Puntuación recurso: " + str(self.punt_nodo) + "<br>Puntuación de Vulns: "+ str(self.punt_vuln)+"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Puntuación de SO: " +str(self.punt_SO)+"<br>Puntuación de Puertos: "+str(self.punt_puertos)+"&nbsp;&nbsp;&nbsp;&nbsp;Cult. Org.: " +str(self.cultura_Organizacional)+"<br>Este recurso necesita acción de usuario para explotar vulnerabilidad<br>Probabilidad de error humano: " + str(prob_error_humano) 
            valor = randrange(1,101)
            print("Valor: ",valor," porcentraje: ",prob_error_humano)  
            if valor <= prob_error_humano:
                self.estado = State.COMPROMETIDO
                print("Nodo ",self.ip," Comprometido!")
                self.model.mensaje3 = "El recurso fue comprometido!"
            else:
                self.estado = State.ATACADO
                print("Nodo ",self.ip," Se salvo!")
                self.model.mensaje3 = "El recurso no ha sido comprometido!"
        if self.model.nodos_atacables == 1:
            print("Entramos al ultimo nodo, deberia detenerse rai nau")
            self.model.nodos_atacables = 0

    def step(self):
        if self.first:
            self.first = False
            if self.tipo =="Nodo":
                self.entrega_punt_nodos(self.punt_nodo)
            elif self.tipo == "Central":
                self.promedio_cultura()
        if self.estado == State.EN_ATAQUE:
            self.ataque_nodo()
            
        if self.tipo == "Central" and self.org == self.objetivo:
            self.nodo_mas_debil()
from mesa import Agent, Model
from mesa.time import RandomActivation
from mesa.space import MultiGrid

class ECSAgent(Agent):
    """ An agent with fixed initial wealth."""
    def __init__(self, unique_id, model, info):
        super().__init__(unique_id, model)
        self.info = info
        self.running = True

    def step(self):
        print(self.unique_id)

class ECSModel(Model):
    """A model with some number of agents."""
    def __init__(self, N,width,height,lista):
        self.num_agents = N           
        print(self.num_agents)
        self.running = True
        self.grid = MultiGrid(width, height, True)
        self.schedule = RandomActivation(self)
        # Create agents
        for i in range(self.num_agents):
            a = ECSAgent(lista[i]['ip_str'], self,lista[i])
            self.schedule.add(a)
            x = self.random.randrange(self.grid.width)
            y = self.random.randrange(self.grid.height)
            self.grid.place_agent(a, (x, y))

    def step(self):
        '''Advance the model by one step.'''
        self.schedule.step()

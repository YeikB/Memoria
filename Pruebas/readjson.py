import networkx as nx
import json
from ares import CVESearch
import pandas as pd

cve = CVESearch()


with open(r"445Conce.json", "r") as read_file:
    data = json.load(read_file)
with open(r"cves.json", "r") as read_file:
    cves= json.load(read_file)

df = pd.read_csv('Puertos.csv',sep=';')
print(df.columns)
df = df[["Puertos","Nivel"]]

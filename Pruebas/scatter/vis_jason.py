import json
from plotly.graph_objs import Scattergeo, Layout
from plotly import offline, colors
#Cargando archivo JSON
filename='1_0_month.geojson'


with open(filename) as f:
	load_all = json.load(f)


#Escribiendo archivo JSON bien identado
output_filename='significant_month.geojson'
with open(output_filename,'w') as f2:
	json.dump(load_all,f2,indent=4)

#Revisando cuantos terremotos hay dentro
	registros_terremotos = load_all['features']
	print(f"cantidad de terremotos {len(registros_terremotos)}")

Magnitudes, longitudes, latitudes, hover_text  = [], [] ,[], []
for Feature in registros_terremotos:
	Magnitudes.append(Feature['properties']['mag'])
	longitudes.append(Feature['geometry']['coordinates'][0])
	latitudes.append(Feature['geometry']['coordinates'][1])
	hover_text.append(Feature['properties']['title'])

print(Magnitudes[:10])
print(longitudes[:10])
print(latitudes[:10])

data = [Scattergeo(lon=longitudes, lat=latitudes)]

my_layout=Layout(title='Terremotos globales')
fig = {'data': data, 'layout' : my_layout}
offline.plot(fig, filename='terremotos_globales.html')

#Imprimir escalas de colores diponibles

for key in colors.PLOTLY_SCALES.keys():
	print(key)

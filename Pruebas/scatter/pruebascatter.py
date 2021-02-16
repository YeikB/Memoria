import plotly.io as pio
print(pio.renderers.default)
import plotly.graph_objects as go
fig = go.Figure(
    data=[go.Bar(y=[2, 1, 3])],
    layout_title_text="A Figure Displayed with fig.show()"
)
fig.write_html('tmp.html', auto_open=True)
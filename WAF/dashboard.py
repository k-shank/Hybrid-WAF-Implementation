"""Implements a simple dashboard for the WAF.

The dashboard is built with Dash and Plotly and provides an overview of
recorded requests.  It displays three pie charts showing the distribution of
performed requests, attacks by type, and locations of attacks.  A data
table allows filtering by threat type or location.  Clicking on a pie
segment filters the table, and a reset button clears the filters.  A Flask
endpoint `/review/<id>` renders a Jinja2 template for inspecting an
individual request record.
"""

from __future__ import annotations

import json
import numpy as np
import dash
import dash_core_components as dcc
import dash_html_components as html
import dash_table
from dash.dependencies import Input, Output
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from flask import Flask, render_template

from .request import DBController

# List of possible threat labels used to filter
POSSIBLE_ATTACKS = ['sqli', 'xss', 'cmdi', 'path-traversal', 'valid', 'parameter-tampering']


def generate_figure(df):
    """Generate a Plotly figure with three pie charts summarising the data."""
    fig = make_subplots(rows=1, cols=3, specs=[[{'type': 'domain'}, {'type': 'domain'}, {'type': 'domain'}]])
    fig.layout['clickmode'] = 'event+select'
    # Pie chart for performed requests: group all attacks under 'attack'
    valid_data = df.replace(['sqli', 'xss', 'cmdi', 'path-traversal', 'parameter-tampering'], 'attack')
    data_pie = valid_data['threat_type'].value_counts().to_frame()
    data_pie['type'] = list(data_pie.index)
    data_pie = data_pie.rename(columns={"threat_type": "count"})
    fig.add_trace(go.Pie(labels=data_pie['type'], values=data_pie['count'], title='Performed requests', textposition='inside', textinfo='percent+label'), 1, 1)
    # Pie chart for performed attacks
    attack_data = df[df['threat_type'] != 'valid']
    data_pie = attack_data['threat_type'].value_counts().to_frame()
    data_pie['type'] = list(data_pie.index)
    data_pie = data_pie.rename(columns={"threat_type": "count"})
    fig.add_trace(go.Pie(labels=data_pie['type'], values=data_pie['count'], title='Performed attacks', textposition='inside', textinfo='percent+label'), 1, 2)
    # Pie chart for location of attacks
    data_pie = df['location'].value_counts().to_frame()
    data_pie['type'] = list(data_pie.index)
    data_pie = data_pie.rename(columns={"location": "count"})
    data_pie = data_pie.replace('', np.nan).dropna()
    fig.add_trace(go.Pie(labels=data_pie['type'], values=data_pie['count'], title='Locations of attacks', textposition='inside', textinfo='percent+label'), 1, 3)
    return dcc.Graph(id='example-graph1', figure=fig)


def configure_columns(name: str) -> dict:
    config = {'name': name, 'id': name}
    if name == 'Link':
        config['presentation'] = 'markdown'
    return config


def generate_table(df, label):
    """Return a Dash DataTable filtered by label or location."""
    if label is None:
        data_to_use = df
    elif label == 'attack':
        data_to_use = df[df['threat_type'] != 'valid']
    elif label in POSSIBLE_ATTACKS:
        data_to_use = df[df['threat_type'] == label]
    else:
        data_to_use = df[df['location'] == label]
    return dash_table.DataTable(
        id='data_table',
        columns=[configure_columns(i) for i in data_to_use.drop(['id', 'log_id', 'request'], axis=1).columns],
        data=data_to_use.drop(['id', 'log_id', 'request'], axis=1).to_dict('records'),
        style_cell={
            'overflow': 'hidden',
            'textOverflow': 'ellipsis',
            'maxWidth': 0,
        },
        tooltip_data=[{'request': {'value': str(row['request']), 'type': 'markdown'}} for row in data_to_use.to_dict('rows')],
        tooltip_duration=None,
        page_action="native",
        page_current=0,
        page_size=10,
        filter_action='native',
        cell_selectable=False,
    )


# External CSS for Dash styling
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

server = Flask(__name__)

app = dash.Dash(__name__, external_stylesheets=external_stylesheets, server=server)

app.layout = html.Div(children=[
    html.Div(children=[
        html.H1(children='WAF Dashboard'),
        html.Div(children='Dashboard for simple WAF created in Python!'),
    ]),
    html.Div(id='graph', children=[
        dcc.Graph(id='example-graph1', figure=make_subplots(rows=1, cols=3, specs=[[{'type': 'domain'}, {'type': 'domain'}, {'type': 'domain'}]])),
    ]),
    html.Div(id='table-data', style={'width': '100%'}),
    html.Div(id='reset-button-div', children=[
        html.Button('Clear filters', id='reset-button', n_clicks=0),
    ]),
])


@app.callback([
    Output('table-data', 'children'),
    Output('graph', 'children'),
], [Input('example-graph1', 'clickData'), Input('reset-button', 'n_clicks')])
def display_hover_data(hoverData, n_clicks):
    ctx = dash.callback_context
    component_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None
    db = DBController()
    raw_data = db.read_all()
    db.close()
    label = None
    if component_id == 'example-graph1' and hoverData:
        label = hoverData['points'][0]['label']
    return generate_table(raw_data, label), generate_figure(raw_data)


@server.route('/')
def index():
    return app.index()


@server.route('/review/<int:request_id>', methods=['GET'])
def review_request(request_id: int):
    # Load request body
    with open(f'./requests_log/{request_id}.json', 'r') as f:
        request_json = json.dumps(json.load(f), indent=4)
    db = DBController()
    log, data = db.read_request(int(request_id))
    db.close()
    return render_template('request.html', id=str(request_id), request=request_json, num_attacks=len(data), attacks=data, log=log)


if __name__ == '__main__':
    app.run_server(debug=True)
import pandas as pd
import plotly.express as px
from django_plotly_dash import DjangoDash
from dash import dcc, html
from dash.dependencies import Input, Output
import requests
from datetime import datetime

# Initialize Dash app with Django integration
app = DjangoDash("ThreatChart", suppress_callback_exceptions=True)

# Layout
app.layout = html.Div([
    html.Div([
        html.H1("TowerWatch: Real-Time Threat Monitoring", 
               style={"textAlign": "center", "margin": "10px 0"}),
        html.Div(id='last-updated', 
                style={"textAlign": "center", "marginBottom": "20px"})
    ]),
    dcc.Graph(
        id="threat-level-graph",
        style={
            "width": "100%",
            "height": "85vh",
            "margin": "0",
            "padding": "0"
        }
    ),
    dcc.Store(id='alert-store', data=[]),
    dcc.Interval(
        id="interval-component",
        interval=5000,  # Update every 5 seconds
        n_intervals=0
    )
], style={
    "margin": "0", 
    "padding": "0 20px",
    "overflowX": "hidden",
    "fontFamily": "Arial, sans-serif"
})

# Callback to update alert data
@app.callback(
    [Output('alert-store', 'data'),
     Output('last-updated', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_alerts(n):
    try:
        response = requests.get("http://localhost:8000/api/alerts", timeout=5)
        alerts = response.json()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return alerts, f"Last updated: {timestamp}"
    except Exception as e:
        print(f"Error fetching alerts: {str(e)}")
        return [], f"Error updating: {str(e)}"

# Callback to update chart
@app.callback(
    Output("threat-level-graph", "figure"),
    [Input("alert-store", "data")]
)
def update_chart(alerts):
    if not alerts:
        return px.bar(
            x=["No Data"], 
            y=[0],
            title="Waiting for data...",
            labels={"x": "", "y": ""}
        )
    
    try:
        # Process alerts and determine colors
        data = []
        for alert in alerts:
            score = float(alert.get('threat_score', 0))
            if score <= 0.3:
                color = "green"
                level = "Low"
            elif score <= 0.7:
                color = "orange"
                level = "Medium"
            else:
                color = "red"
                level = "High"
            
            data.append({
                "Alert": alert.get('alert', 'Unknown').replace('_', ' ').title(),
                "Threat Score": score,
                "Level": level,
                "color": color,
                "Details": f"Score: {score:.2f} | Level: {level}"
            })
        
        df = pd.DataFrame(data)
        
        if df.empty:
            return px.bar(
                x=["No Data"], 
                y=[0],
                title="No active threats detected",
                labels={"x": "", "y": ""}
            )
        
        # Create the bar chart
        fig = px.bar(
            df,
            x="Alert",
            y="Threat Score",
            color="Level",
            color_discrete_map={
                "Low": "#4CAF50",
                "Medium": "#FF9800",
                "High": "#F44336"
            },
            hover_data=["Details"],
            title="Active Threat Dashboard",
            text="Threat Score",
            height=700
        )
        
        # Update layout
        fig.update_layout(
            yaxis=dict(range=[0, 1.1]),  # Slight padding at the top
            showlegend=True,
            xaxis_title="",
            yaxis_title="Threat Score (0-1)",
            title_x=0.5,
            margin=dict(l=20, r=20, t=80, b=100),  # Extra space at bottom for x-labels
            font=dict(
                family="Arial, sans-serif",
                size=14,
                color="#333"
            ),
            plot_bgcolor='rgba(0,0,0,0.02)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis_tickangle=-45,  # Angle x-axis labels for better readability
            uniformtext_minsize=10,
            uniformtext_mode='hide'
        )
        
        # Format the text on bars
        fig.update_traces(
            texttemplate='%{y:.2f}',
            textposition='outside',
            cliponaxis=False  # Prevent text from being clipped
        )
        
        return fig
        
    except Exception as e:
        print(f"Error updating chart: {str(e)}")
        return px.bar(
            x=["Error"], 
            y=[0], 
            title="Error loading threat data - Please try again later",
            labels={"x": "", "y": ""}
        )
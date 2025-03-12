import pandas as pd
import plotly.express as px
from jinja2 import Template
import os

def docs(dtl, dtu, comp):
    csv_file_path = 'SecurityEvents Summary.csv'
    df = pd.read_csv(csv_file_path)
    df['host'].fillna("No hostname", inplace=True)

    webapps = df['webApp'].unique()
    
    charts = {}
    violation_counts = {}
    country_counts = {}
    uri_counts = {}
    host_counts = {}
    
    for webapp in webapps:
        subset = df[df['webApp'] == webapp]
        
        top_violations = subset.groupby('violationType').size().reset_index(name='count').nlargest(7, 'count')
        top_violations['percentage'] = (top_violations['count'] / top_violations['count'].sum()) * 100
        violation_counts[webapp] = top_violations.to_dict('records')
        fig1 = px.pie(top_violations, names='violationType', values='count', title=f'Attacks by attack type - {webapp}', hole=0.3)
        
        top_countries = subset.groupby('Country Code').size().reset_index(name='count').nlargest(7, 'count')
        top_countries['percentage'] = (top_countries['count'] / top_countries['count'].sum()) * 100
        country_counts[webapp] = top_countries.to_dict('records')
        fig2 = px.pie(top_countries, names='Country Code', values='count', title=f'Hit by Country - {webapp}', hole=0.3)
        
        top_uris = subset.groupby('uri').size().reset_index(name='count').nlargest(7, 'count')
        uri_counts[webapp] = top_uris.to_dict('records')
        fig3 = px.bar(top_uris, x='uri', y='count', title=f'Top attacked URIs by Host - {webapp}')
        
        top_hosts = subset.groupby('host').size().reset_index(name='count').nlargest(7, 'count')
        top_hosts['percentage'] = (top_hosts['count'] / top_hosts['count'].sum()) * 100
        host_counts[webapp] = top_hosts.to_dict('records')
        fig4 = px.pie(top_hosts, names='host', values='count', title=f'Top 7 Hosts - {webapp}', hole=0.3)
        
        charts[webapp] = {'fig1': fig1.to_html(full_html=False), 'fig2': fig2.to_html(full_html=False), 'fig3': fig3.to_html(full_html=False), 'fig4': fig4.to_html(full_html=False)}
    
    # Jinja2 template for interactive HTML report
    template = Template('''
    <html>
    <head>
        <title>Security Report</title>
        <style>
            body { font-family: Arial, sans-serif; }
            .header { background-color: #a7c7e7; color: white; padding: 10px; text-align: center; }
            h1, h2 { margin-bottom: 20px; }
            h3 { margin-top: 40px; color: brown; font-size: 24px; font-weight: bold; }
            h4 { margin-top: 20px; color: #A9A9A9; font-size: 20px }
            table { font-size: 16px; margin: 0 auto; border-collapse: collapse; }
            th, td { padding: 10px; text-align: center; border: 1px solid black; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{{ company }}</h1>
            <h2>From {{ start_date }} to {{ end_date }}</h2>
        </div>
        {% for webapp in webapps %}
            <h3>{{ webapp }}</h3>
            <h4>Attacks by attack type</h4>
            {{ charts[webapp]['fig1'] | safe }}
            <table>
                <tr><th>Violation Type</th><th>Count</th></tr>
                {% for row in violation_counts[webapp] %}
                    <tr><td>{{ row.violationType }}</td><td>{{ row.count }}</td></tr>
                {% endfor %}
            </table>
            
            <h4>Top 7 Hosts</h4>
            {{ charts[webapp]['fig4'] | safe }}
            <table>
                <tr><th>Host</th><th>Count</th></tr>
                {% for row in host_counts[webapp] %}
                    <tr><td>{{ row.host }}</td><td>{{ row.count }}</td></tr>
                {% endfor %}
            </table>
            
            <h4>Hits by Country</h4>
            {{ charts[webapp]['fig2'] | safe }}
            <table>
                <tr><th>Country Code</th><th>Count</th></tr>
                {% for row in country_counts[webapp] %}
                    <tr><td>{{ row['Country Code'] }}</td><td>{{ row.count }}</td></tr>
                {% endfor %}
            </table>
            
            <h4>Top attacked URIs by Host</h4>
            {{ charts[webapp]['fig3'] | safe }}
            <table>
                <tr><th>URI</th><th>Count</th></tr>
                {% for row in uri_counts[webapp] %}
                    <tr><td>{{ row.uri }}</td><td>{{ row.count }}</td></tr>
                {% endfor %}
            </table>
        {% endfor %}
    </body>
    </html>
    ''')

    # Render template
    html_report = template.render(company=comp, start_date=dtl, end_date=dtu, webapps=webapps, charts=charts,
                                  violation_counts=violation_counts, country_counts=country_counts,
                                  uri_counts=uri_counts, host_counts=host_counts)

    # Save to file
    with open("CW_Report.html", "w", encoding="utf-8") as file:
        file.write(html_report)
    
    print("Interactive report generated: CW_Report.html")

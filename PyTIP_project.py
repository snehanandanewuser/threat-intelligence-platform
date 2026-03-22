# PyTIP_project.py - Threat Intelligence Platform (TIP) Integrated Web Code

import os
from dotenv import load_dotenv

load_dotenv()
from flask import Flask, render_template, request, send_file  # ADDED 'send_file'
import requests
import json
import sqlite3
import pandas as pd
# Imports for Charting
import plotly.express as px
import plotly.offline as py

# Initialize the Flask application
app = Flask(__name__)

# --- 1. CONFIGURATION ---
# *** IMPORTANT: PASTE YOUR KEYS BELOW ***
OTX_API_KEY = os.getenv("OTX_API_KEY")  # <-- Replace this with your AlienVault OTX key
VT_API_KEY = os.getenv("VT_API_KEY")  # <-- Replace this with your VirusTotal key

# Test Indicators for a complete demonstration
TEST_IP = "185.220.101.37"
TEST_HASH = "c0202cf6aeab8437c638533d14563d35"
DB_NAME = 'threat_intelligence.db'


# --- 2. DATA ACQUISITION & NORMALIZATION (The Connectors) ---

def fetch_otx_pulse(indicator, indicator_type):
    """Fetches, scores, and normalizes IP data from AlienVault OTX."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        if data.get('pulse_info') and data['pulse_info'].get('count', 0) > 0:
            pulse_count = data['pulse_info']['count']
            if pulse_count >= 10:
                confidence = "HIGH (Confirmed Threat)"
            elif pulse_count >= 3:
                confidence = "MEDIUM (Multiple Reports)"
            else:
                confidence = "LOW (Initial Report)"

            normalized_iocs = []
            pulses = data['pulse_info']['pulses']
            for pulse in pulses[:3]:
                ioc_data = {
                    "indicator": indicator,
                    "type": indicator_type,
                    "source": "AlienVault OTX",
                    "pulse_name": pulse.get('name'),
                    "threat_tags": ", ".join(pulse.get('tags', [])),
                    "reference_link": f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
                    "confidence_score": confidence
                }
                normalized_iocs.append(ioc_data)
            return normalized_iocs
        else:
            return []
    except requests.exceptions.RequestException:
        return []


def fetch_virustotal_report(ioc_hash):
    """Fetches and normalizes file hash analysis data from VirusTotal."""
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{ioc_hash}"
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()

        if response.status_code == 404:
            return []

        data = response.json().get('data', {}).get('attributes', {})
        if data:
            stats = data.get('last_analysis_stats', {})
            positives = stats.get('malicious', 0)

            if positives > 20:
                confidence = f"CRITICAL ({positives} detections)"
            elif positives > 5:
                confidence = f"HIGH ({positives} detections)"
            else:
                confidence = "LOW (Few Detections)"

            ioc_data = {
                "indicator": ioc_hash,
                "type": "File Hash (MD5)",
                "source": "VirusTotal",
                "pulse_name": data.get('type_description', 'N/A'),
                "threat_tags": f"VT Positives: {positives}",
                "reference_link": f"https://www.virustotal.com/gui/file/{ioc_hash}/details",
                "confidence_score": confidence
            }
            return [ioc_data]
        else:
            return []
    except requests.exceptions.RequestException:
        return []


# --- 3. DATA STORAGE & MANAGEMENT (SQLite) ---

def setup_database():
    """Sets up the SQLite database and the IOCs table."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY,
            indicator TEXT NOT NULL UNIQUE,
            type TEXT,
            source TEXT,
            pulse_name TEXT,
            threat_tags TEXT,
            confidence_score TEXT,
            reference_link TEXT,
            ingestion_date DATE DEFAULT CURRENT_DATE
        )
    """)
    conn.commit()
    conn.close()


def store_iocs(iocs_list):
    """Stores a list of normalized IOCs into the database, handling duplicates."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    for ioc in iocs_list:
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO iocs (
                    indicator, type, source, pulse_name, threat_tags, confidence_score, reference_link
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ioc['indicator'], ioc['type'], ioc['source'], ioc['pulse_name'],
                ioc['threat_tags'], ioc['confidence_score'], ioc['reference_link']
            ))
        except sqlite3.Error:
            pass
    conn.commit()
    conn.close()


def query_iocs(query_term=""):
    """Queries the database for IOCs, fetching results, using the search term if provided."""
    conn = sqlite3.connect(DB_NAME)

    if query_term:
        # Secure SQL query for Server-Side Search
        sql_query = """
            SELECT * FROM iocs 
            WHERE indicator LIKE ? OR threat_tags LIKE ? OR source LIKE ? OR confidence_score LIKE ?
            ORDER BY ingestion_date DESC
        """
        # The argument list includes wildcards for LIKE matching
        search_arg = '%' + query_term + '%'
        df = pd.read_sql_query(sql_query, conn, params=(search_arg, search_arg, search_arg, search_arg))
    else:
        # Default query: fetch latest 50 records if no search term is present
        sql_query = "SELECT * FROM iocs ORDER BY ingestion_date DESC LIMIT 50"
        df = pd.read_sql_query(sql_query, conn)

    conn.close()
    return df


# --- 4. DATA VISUALIZATION (Chart Generator) ---

def create_confidence_chart():
    """Generates an interactive bar chart of Confidence Score distribution,
       always querying the full data set."""

    conn = sqlite3.connect(DB_NAME)
    # Query the whole table to count all confidence scores (ignores search filter)
    df = pd.read_sql_query(
        "SELECT confidence_score, COUNT(confidence_score) as count FROM iocs GROUP BY confidence_score", conn)
    conn.close()

    if df.empty:
        return "<p>No data available for charting.</p>"

    # Define a consistent sorting order for the bars (CRITICAL > HIGH > MEDIUM > LOW)
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    # Clean the score column (e.g., reduce 'CRITICAL (60 detections)' to just 'CRITICAL')
    df['confidence_score'] = df['confidence_score'].str.split(' ').str[0]

    # Filter and Sort the DataFrame
    df['confidence_score'] = pd.Categorical(df['confidence_score'], categories=order, ordered=True)
    df = df.sort_values('confidence_score').dropna(subset=['confidence_score'])

    # Define colors for the chart
    color_map = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'gold', 'LOW': 'green'}

    # Calculate the maximum count to set a suitable Y-axis limit (CHART FIX)
    max_count = df['count'].max() if not df.empty else 1
    y_max = max_count + 0.5

    # Create the Plotly bar chart
    fig = px.bar(df,
                 x='confidence_score',
                 y='count',
                 color='confidence_score',
                 color_discrete_map=color_map,
                 title='IOC Confidence Score Distribution',
                 labels={'confidence_score': 'Confidence Level', 'count': 'Number of Indicators'},
                 text='count')

    # Force Y-axis to start at 0 and end correctly
    fig.update_yaxes(range=[0, y_max], fixedrange=True)

    # Convert the Plotly figure to an HTML string
    # CRITICAL FIX: Force inclusion of the CDN inside the chart's HTML block
    chart_html = py.plot(fig, output_type='div', include_plotlyjs='cdn')
    return chart_html


# --- 5. FLASK WEB DASHBOARD (The Dissemination) ---

@app.route('/')
def dashboard():
    """Runs the data collection, queries the database, and renders the web template."""
    setup_database()

    # 1. Get the search term from the URL
    search_term = request.args.get('query', '')

    # --- Automated Data Collection Run (Runs when dashboard loads) ---
    otx_iocs = fetch_otx_pulse(TEST_IP, "IPv4")
    vt_iocs = fetch_virustotal_report(TEST_HASH)

    all_new_iocs = otx_iocs + vt_iocs

    if all_new_iocs:
        store_iocs(all_new_iocs)
    # -----------------------------------------------------------------

    # 2. Query the processed data from SQLite (uses the search_term for table data)
    results_df = query_iocs(search_term)

    # 3. Prepare data for the HTML template
    indicators = results_df.to_dict('records')
    display_cols = ['indicator', 'type', 'source', 'threat_tags', 'confidence_score', 'ingestion_date']
    headers = [col.replace('_', ' ').title() for col in display_cols]

    # Generate the chart HTML (always uses the full data set, with y-axis fix and CDN inclusion)
    confidence_chart = create_confidence_chart()

    # 4. Render the HTML template
    return render_template('dashboard.html',
                           indicators=indicators,
                           headers=headers,
                           search_term=search_term,
                           confidence_chart=confidence_chart)


# --- 6. DATA EXPORT FUNCTION ---

@app.route('/export')
def export_data():
    """Queries the database (using the current search filter) and exports to CSV."""

    search_term = request.args.get('query', '')

    # Run the existing query function
    df = query_iocs(search_term)

    # --- DATE FIX: Convert date column to a simple string format for better CSV compatibility ---
    df['ingestion_date'] = pd.to_datetime(df['ingestion_date']).dt.strftime('%Y-%m-%d')

    # Drop the ID and Reference Link columns for cleaner export
    export_cols = ['indicator', 'type', 'source', 'threat_tags', 'confidence_score', 'ingestion_date']
    df_export = df[export_cols]

    export_filename = "tip_export_iocs.csv"

    # Save the DataFrame to a temporary CSV file
    df_export.to_csv(export_filename, index=False)

    # Return the file as a downloadable attachment
    return send_file(
        export_filename,
        mimetype='text/csv',
        as_attachment=True,
        download_name=export_filename
    )


# --- 7. SERVER STARTUP ---
if __name__ == "__main__":
    print("\n--- Starting Threat Intelligence Platform Web Server ---")
    print("Serving dashboard at: http://127.0.0.1:5000/")
    app.run(debug=True)
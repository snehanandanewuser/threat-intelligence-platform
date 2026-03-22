# Automated Tactical Threat Intelligence Platform (TIP)

## 🛡️ Project Overview
This platform is a specialized cybersecurity tool designed to automate the collection and normalization of threat data. It helps security analysts prioritize threats by pulling real-time data from intelligence sources like AlienVault OTX and VirusTotal.

## 🚀 Key Features
* **Automated Data Acquisition**: Automatically fetches threat indicators (IPs, Hashes) using professional APIs.
* **Threat Normalization**: Converts raw data into a structured format for easier analysis.
* **Interactive Dashboard**: A web-based interface built with Flask to visualize current threats.
* **Tactical Prioritization**: Scores threats based on confidence levels to identify high-risk indicators.

## 🛠️ Tech Stack
* **Language**: Python 3.11
* **Framework**: Flask (Web Dashboard)
* **APIs**: AlienVault OTX, VirusTotal
* **Database**: SQLite3

## 🔒 Security & Installation

This project uses **Environment Variables** to protect sensitive API keys. 

1. **Clone the repository.**
2. **Install dependencies:** `pip install -r requirements.txt`
3. **Setup Secrets:** Create a `.env` file in the root directory and add your keys:  
   `OTX_API_KEY=your_key_here`  
   `VT_API_KEY=your_key_here`  
4. **Run the application:** `python PyTIP_project.py`  


# Automated SOC IP Enrichment Tool

## Overview
A Python-based security automation tool designed to accelerate SOC analyst workflows. This script accepts a suspicious IP address via the command line, concurrently queries multiple threat intelligence APIs, and outputs a normalized, SOAR-compatible JSON payload for automated ticketing and triage.

## Features
* **Dynamic API Integration:** Queries VirusTotal and AbuseIPDB for threat enrichment.
* **Automated Triage Logic:** Calculates a dynamic severity score (Low, Medium, High) based on vendor flags and confidence metrics.
* **SOAR Ready:** Outputs structured JSON designed for ingestion into SOAR platforms (e.g., Splunk SOAR, Cortex XSOAR) to trigger automated playbooks.
* **Secure Configuration:** Utilizes environment variables (`.env`) to prevent credential leakage.

## Requirements
* Python 3.x
* `requests`
* `python-dotenv`

## Installation
1. Clone the repository:
   `git clone https://github.com/abhay7yy/threat-intel-enricher.git`
2. Create and activate a virtual environment:
   `python3 -m venv venv`
   `source venv/bin/activate`
3. Install dependencies:
   `pip install requests python-dotenv`
4. Create a `.env` file in the root directory and add your API keys:
   ```text
   VT_API_KEY=your_virustotal_key
   ABUSE_API_KEY=your_abuseipdb_key

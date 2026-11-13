import os
import json
import requests
import argparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        malicious = data['data']['attributes']['last_analysis_stats']['malicious']
        total = sum(data['data']['attributes']['last_analysis_stats'].values())
        # Return a dictionary instead of printing
        return {"malicious_flags": malicious, "total_scans": total}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        data = response.json()
        # Return a dictionary instead of printing
        return {
            "confidence_score": data['data']['abuseConfidenceScore'],
            "total_reports": data['data']['totalReports']
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def generate_soar_ticket(ip, vt_data, abuse_data):
    # Basic logic to determine severity based on API results
    severity = "Low"
    if vt_data.get("malicious_flags", 0) > 0 or abuse_data.get("confidence_score", 0) > 0:
        if vt_data.get("malicious_flags", 0) > 3 or abuse_data.get("confidence_score", 0) > 50:
            severity = "High"
        else:
            severity = "Medium"

    # Construct the final JSON payload
    ticket = {
        "alert_type": "Suspicious IP Enrichment",
        "indicator": ip,
        "calculated_severity": severity,
        "enrichment_sources": {
            "virustotal": vt_data,
            "abuseipdb": abuse_data
        },
        "recommended_action": "Block at perimeter firewall" if severity == "High" else "Continue monitoring"
    }
    
    # json.dumps() converts the Python dictionary into a beautifully formatted JSON string
    print(json.dumps(ticket, indent=4))

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Automated SOC IP Enrichment Tool")
    parser.add_argument("ip", help="The suspicious IP address to investigate")

    # Parse the arguments provided in the terminal
    args = parser.parse_args()

    if not VT_API_KEY or not ABUSE_API_KEY:
        print("Error: Missing API keys in .env file.")
    else:
        # Pass the IP from the terminal into function

        vt_results = check_virustotal(args.ip)
        abuse_results = check_abuseipdb(args.ip)
        
        # 2. Generate the ticket
        generate_soar_ticket(args.ip, vt_results, abuse_results)
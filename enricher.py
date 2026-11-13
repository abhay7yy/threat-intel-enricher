import os
import requests
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

# Hardcoded IP for initial testing
TARGET_IP = "8.8.8.8" 

def check_virustotal(ip):
    print(f"Checking {ip} against VirusTotal...")
    
    # The specific API endpoint for IP addresses
    url = f"https://virustotal.com/api/v3/ip_addresses/{ip}"

    # VirusTotal requires the API key to be passed in a header named 'x-apikey'
    headers = {
        "x-apikey": VT_API_KEY
    } 

    try:
        # Send the GET request
        response = requests.get(url,headers=headers)

        # This will automatically trigger an error if the API rejects our request (bad key, rate limit)
        response.raise_for_status()

        # Convert the raw response into a Py dictionary
        data = response.json()

        # Drill down into the JSON structure to find the specific "malicious" score
        malicious_votes = data['data']['attributes']['last_analysis_stats']['malicious']
        total_votes = sum(data['data']['attributes']['last_analysis_stats'].values())

        print(f"VirusTotal Result: {malicious_votes} out of {total_votes} security vendors flagged this IP as malicious.")

    except requests.exceptions.RequestException as e:
        print(f"Error querying VirusTotal: {e}")    

if __name__ == "__main__":
    if not VT_API_KEY or not ABUSE_API_KEY:
        print("Error: Missing API keys in .env file.")
    else:
        check_virustotal(TARGET_IP)
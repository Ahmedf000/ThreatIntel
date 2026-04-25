import requests
import argparse

from dotenv import load_dotenv
from colors.color import Colors
import sys
import json
import os

load_dotenv()
API_KEY = os.getenv("VT_API")
if not API_KEY:
    print("[!] Error: API credentials not found!")
    print("[!] Make sure .env file exists with Virus Total API Key...Register :)")
    sys.exit(1)


def request_reputation(domain):
    """Adjustment taken from VIRUS TOTAL WEBSITE"""
    url = f"https://www.virustotal.com/api/v3/urls"

    HEADERS = {
        'accept': 'application/json',
        'x-apikey': API_KEY,
        'content-type': 'application/x-www-form-urlencoded',
    }
    res = requests.post(url,
                        headers=HEADERS,
                        data={"url": domain})

    if res.status_code != 200:
        print(f"Issue within POST request: {res.status_code}")
        return None

    analysis_id = res.json()['data']['id']
    print(Colors.yellow(f"[*] Analysis ID Submitted: {analysis_id}"))

    #get method
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    analysis_response = requests.get(analysis_url, headers={'accept': 'application/json', 'x-apikey': API_KEY})
    if analysis_response.status_code != 200:
        print(f"Issue within GET request: {analysis_response.status_code}")
        return None

    scanned_url = {
        'url': analysis_response.json()['data']['attributes']['url'] if analysis_response.json()['data']['attributes']['url'] else "N/A",
        'Undetected': analysis_response.json()['data']['attributes']['stats']['undetected'] if analysis_response.json()['data']['attributes']['stats']['undetected'] else "N/A",
        'harmless': analysis_response.json()['data']['attributes']['stats']['harmless'] if analysis_response.json()['data']['attributes']['stats']['harmless'] else "N/A",
        'suspicious': analysis_response.json()['data']['attributes']['stats']['suspicious'],
        'malicious': analysis_response.json()['data']['attributes']['stats']['malicious']
    }

    return scanned_url #gave "url": "http://github.com/", not https...
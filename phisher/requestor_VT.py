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

    clean_domain = domain.replace("https://", "").replace("http://", "").strip("/")

    for scheme in ["http", "https"]:
        url_to_check = f"{scheme}://{clean_domain}"
        print(Colors.yellow(f"[*] Trying {url_to_check}..."))

        url = f"https://www.virustotal.com/api/v3/urls"

        HEADERS = {
            'accept': 'application/json',
            'x-apikey': API_KEY,
            'content-type': 'application/x-www-form-urlencoded',
        }
        res = requests.post(url,
                            headers=HEADERS,
                            data={"url": url_to_check})

        if res.status_code != 200:
            if scheme == "https":
                print(Colors.orange(f"[!] HTTPS failed — site may not have SSL certificate"))
            continue

        analysis_id = res.json()['data']['id']
        print(Colors.yellow(f"[*] Analysis ID Submitted: {analysis_id}"))

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(
            analysis_url,
            headers={'accept': 'application/json', 'x-apikey': API_KEY}
        )

        if analysis_response.status_code != 200:
            continue

        attrs = analysis_response.json()['data']['attributes']
        return {
            'url': url_to_check,  # use what WE sent, not what VT normalizes back
            'Undetected': attrs['stats']['undetected'],
            'harmless': attrs['stats']['harmless'],
            'suspicious': attrs['stats']['suspicious'],
            'malicious': attrs['stats']['malicious']
        }

    print(Colors.red(f"[!] Both https and http failed for {clean_domain}"))
    return None



import requests
import argparse
import time

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

    for scheme in ["https", "http"]:
        url_to_check = f"{scheme}://{clean_domain}"
        print(Colors.yellow(f"[*] Trying {url_to_check}..."))

        url = "https://www.virustotal.com/api/v3/urls"

        HEADERS = {
            'accept': 'application/json',
            'x-apikey': API_KEY,
            'content-type': 'application/x-www-form-urlencoded',
        }
        res = requests.post(url, headers=HEADERS, data={"url": url_to_check})

        if res.status_code != 200:
            if scheme == "https":
                print(Colors.orange(f"[!] HTTPS failed - site may not have SSL certificate"))
            continue

        analysis_id = res.json()['data']['id']
        print(Colors.yellow(f"[*] Analysis ID Submitted: {analysis_id}"))
        print(Colors.yellow(f"[*] Waiting for VT analysis to complete..."))

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        max_retries = 6
        wait_seconds = 5

        for attempt in range(max_retries):
            time.sleep(wait_seconds)

            analysis_response = requests.get(
                analysis_url,
                headers={'accept': 'application/json', 'x-apikey': API_KEY}
            )

            if analysis_response.status_code != 200:
                continue

            data = analysis_response.json()
            status = data.get('data', {}).get('attributes', {}).get('status', '')

            if status == 'completed':
                attrs = data['data']['attributes']
                return {
                    'url': url_to_check,
                    'Undetected': attrs['stats']['undetected'],
                    'harmless':   attrs['stats']['harmless'],
                    'suspicious': attrs['stats']['suspicious'],
                    'malicious':  attrs['stats']['malicious']
                }
            else:
                print(Colors.yellow(f"[*] Analysis status: {status} - retrying ({attempt + 1}/{max_retries})..."))

        print(Colors.orange(f"[!] Analysis did not complete in time for {url_to_check} - returning partial result"))
        attrs = analysis_response.json().get('data', {}).get('attributes', {})
        stats = attrs.get('stats', {})
        return {
            'url': url_to_check,
            'Undetected': stats.get('undetected', 0),
            'harmless':   stats.get('harmless', 0),
            'suspicious': stats.get('suspicious', 0),
            'malicious':  stats.get('malicious', 0)
        }

    print(Colors.red(f"[!] Both https and http failed for {clean_domain}"))
    return None
import requests
import time
import os
from dotenv import load_dotenv
from colors.color import Colors

# Load .env once at import time so VT_API is available everywhere
load_dotenv()

_VT_SUBMIT_URL  = "https://www.virustotal.com/api/v3/urls"
_VT_ANALYSE_URL = "https://www.virustotal.com/api/v3/analyses/{}"
_MAX_POLL       = 8          # polling attempts after submission
_POLL_WAIT      = 6          # seconds between polls
_RATE_WAIT      = 16         # seconds to wait after a 429


def _get_key() -> str | None:
    key = os.getenv("VT_API")
    if not key:
        print(Colors.red("[!] VT_API not set in .env — skipping VirusTotal lookup."))
        print(Colors.yellow("    Add:  VT_API=your_key_here  to your .env file."))
    return key


def _submit(url_to_check: str, api_key: str) -> str | None:
    """Submit a URL/IP to VT and return the analysis ID, or None on failure."""
    headers = {
        "accept":       "application/json",
        "x-apikey":     api_key,
        "content-type": "application/x-www-form-urlencoded",
    }
    try:
        r = requests.post(_VT_SUBMIT_URL, headers=headers,
                          data={"url": url_to_check}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(Colors.red(f"  [!] Network error submitting to VT: {e}"))
        return None

    if r.status_code == 200:
        analysis_id = r.json().get("data", {}).get("id")
        if analysis_id:
            print(Colors.yellow(f"  [*] Submitted → analysis ID: {analysis_id}"))
            return analysis_id
        print(Colors.red("  [!] VT response 200 but no analysis ID in body."))
        return None

    if r.status_code == 401:
        print(Colors.red("  [!!!] VT returned 401 Unauthorized — your API key is invalid or expired."))
        print(Colors.yellow("        Check VT_API in your .env file."))
        return None

    if r.status_code == 429:
        print(Colors.orange(f"  [!] VT rate-limit hit (429). Waiting {_RATE_WAIT}s then retrying once…"))
        time.sleep(_RATE_WAIT)
        try:
            r2 = requests.post(_VT_SUBMIT_URL, headers=headers,
                               data={"url": url_to_check}, timeout=15)
            if r2.status_code == 200:
                analysis_id = r2.json().get("data", {}).get("id")
                if analysis_id:
                    print(Colors.yellow(f"  [*] Submitted (retry) → analysis ID: {analysis_id}"))
                    return analysis_id
        except requests.exceptions.RequestException:
            pass
        print(Colors.red("  [!] Still rate-limited after retry. Skipping this entry."))
        return None

    print(Colors.red(f"  [!] VT submission failed — HTTP {r.status_code}: {r.text[:120]}"))
    return None


def _poll(analysis_id: str, api_key: str) -> dict | None:
    """Poll VT until analysis completes; return stats dict or None."""
    url = _VT_ANALYSE_URL.format(analysis_id)
    headers = {"accept": "application/json", "x-apikey": api_key}
    last_data = None

    for attempt in range(1, _MAX_POLL + 1):
        time.sleep(_POLL_WAIT)
        try:
            r = requests.get(url, headers=headers, timeout=15)
        except requests.exceptions.RequestException as e:
            print(Colors.red(f"  [!] Network error polling VT: {e}"))
            continue

        if r.status_code == 429:
            print(Colors.orange(f"  [!] Rate-limit during poll. Waiting {_RATE_WAIT}s…"))
            time.sleep(_RATE_WAIT)
            continue

        if r.status_code != 200:
            print(Colors.red(f"  [!] Poll returned HTTP {r.status_code}"))
            continue

        last_data = r.json()
        status = last_data.get("data", {}).get("attributes", {}).get("status", "")
        print(Colors.yellow(f"  [*] Poll {attempt}/{_MAX_POLL} — status: {status}"))

        if status == "completed":
            attrs = last_data["data"]["attributes"]
            return attrs.get("stats", {})

    # Return whatever we have even if not "completed"
    if last_data:
        attrs = last_data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {})
        if stats:
            print(Colors.orange("  [!] Analysis timed out — returning partial result."))
            return stats

    print(Colors.red("  [!] VT analysis never completed."))
    return None


def request_reputation(target: str) -> dict | None:
    """
    Submit a URL or IP to VirusTotal and return:
      {'url': str, 'malicious': int, 'suspicious': int,
       'harmless': int, 'Undetected': int}
    or None on any failure.

    Accepts:
      • Full URLs:  https://example.com/path
      • Bare domains: example.com
      • IP addresses: 1.2.3.4   (do NOT wrap in https:// — pass bare)
    """
    api_key = _get_key()
    if not api_key:
        return None

    # Normalise: strip accidental scheme from bare IPs/domains so we
    # control exactly what gets submitted.
    clean = target.replace("https://", "").replace("http://", "").strip("/")

    # Decide what to actually submit
    is_ip = bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', clean))

    if is_ip:
        candidates = [clean]          # submit bare IP — VT accepts it
    else:
        # Try https first, fall back to http for domains/URLs
        candidates = [f"https://{clean}", f"http://{clean}"]

    import re  # local import to avoid circular at top-level for the regex above

    for candidate in candidates:
        print(Colors.yellow(f"\n[*] Querying VirusTotal for: {candidate}"))
        analysis_id = _submit(candidate, api_key)
        if not analysis_id:
            continue

        stats = _poll(analysis_id, api_key)
        if stats is None:
            continue

        return {
            "url":        candidate,
            "malicious":  stats.get("malicious",  0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless",   0),
            "Undetected": stats.get("undetected", 0),
        }

    print(Colors.red(f"[!] VT lookup failed for: {target}"))
    return None

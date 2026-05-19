import requests
import bs4
import os
import re
import base64
import quopri
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import unquote, urlparse
from pathlib import Path
from dotenv import load_dotenv
import sys
from colors.color import Colors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL_SHORTENERS_LIST = [
    "bit.ly", "tinyurl.com", "t.ly", "rebrand.ly", "is.gd", "goo.su",
    "qrco.de", "clck.ru", "cutt.ly", "rb.gy", "dub.sh", "short.io",
    "ow.ly", "tiny.cc", "spoo.me", "kutt.it", "buff.ly", "bitly.com",
    "shorte.st", "adf.ly", "u.to", "git.io", "t.co", "fb.me", "t.me",
    "shortcm.li", "tny.im", "chilp.it", "y2u.be", "shorturl.at"
]

SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.scr',
    '.hta', '.msi', '.iso', '.lnk', '.wsf', '.sh', '.docm', '.xlsm'
]

NOISE_DOMAINS = [
    "jquery", "bootstrap", "googleapis", "gstatic", "w3.org",
    "schema.org", "facebook.net", "cdn.jsdelivr", "unpkg.com", "cdnjs"
]

PHISHING_PATTERNS = [
    (r"\blogin\b",                                    "Login form detected"),
    (r"\bpassword\b",                                 "Password field detected"),
    (r"\bcredential",                                 "Credential harvesting indicator"),
    (r"\bsignin\b|sign[- ]in",                        "Sign-in form detected"),
    (r"\bverif",                                      "Verification page detected"),
    (r"update.*payment|payment.*update",              "Payment update page"),
    (r"paypal",                                       "PayPal impersonation possible"),
    (r"microsoft|office\s?365|outlook",               "Microsoft impersonation possible"),
    (r"google|gmail",                                 "Google impersonation possible"),
    (r"apple\.com|icloud",                            "Apple impersonation possible"),
    (r"amazon",                                       "Amazon impersonation possible"),
    (r"bankofamerica|wellsfargo|chase|hsbc|barclays",  "Banking impersonation possible"),
    (r"docusign|dropbox|sharepoint",                  "Cloud service impersonation possible"),
]

BROWSER_HEADERS = {
    "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control":             "max-age=0",
}


def _resolve_eml(file):
    candidate = os.path.expanduser(str(file).strip())
    if candidate.endswith('.eml'):
        candidate = candidate[:-4]

    def try_path(p):
        full = Path(str(p) + '.eml')
        return full if full.exists() else None

    return (
        str(found) if (found := try_path(candidate)) else
        str(found) if (found := try_path(Path.cwd() / Path(candidate).name)) else
        str(found) if (found := try_path(Path.home() / 'Desktop' / Path(candidate).name)) else
        (_ for _ in ()).throw(FileNotFoundError(
            f"[!] Could not find '{Path(candidate).name}.eml' in given path, "
            f"{Path.cwd()}, or Desktop."
        ))
    )


def _clean_url(url):
    url = url.strip().rstrip(".,;)'\">/")
    url = re.sub(r'=\n', '', url)
    url = url.replace('=3D', '=').replace('=3d', '=')
    url = re.sub(r'\s+', '', url)
    return unquote(url)


def _is_suspicious_ext(url):
    path = urlparse(url).path.lower()
    return next((e for e in SUSPICIOUS_EXTENSIONS if path.endswith(e)), None)


def _url_key(u):
    key = re.sub(r'[?&][^=]+=\S*', '', u).rstrip('?&')
    return key


def _collect_all_redirects(script_text, raw_content, get_html):
    found = []

    JS_REDIRECT_PATTERNS = [
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']{8,})["\']',
        r'(?:location|document\.location)\.(?:replace|assign)\s*\(\s*["\']([^"\']{8,})["\']',
        r'(?:location|document\.location|self\.location|top\.location|parent\.location)\s*=\s*["\']([^"\']{8,})["\']',
        r'window\.open\s*\(\s*["\']([^"\']{8,})["\']',
        r'history\.pushState\s*\([^,]*,[^,]*,\s*["\']([^"\']{8,})["\']',
        r'setTimeout\s*\(.*?(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']{8,})["\'].*?\d+\s*\)',
        r'setInterval\s*\(.*?(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']{8,})["\'].*?\d+\s*\)',
        r'fetch\s*\(\s*["\']([^"\']{8,})["\']',
    ]

    if script_text:
        for pat in JS_REDIRECT_PATTERNS:
            for m in re.finditer(pat, script_text, re.IGNORECASE | re.DOTALL):
                url = _clean_url(m.group(1))
                if url.startswith('http'):
                    found.append(('JS redirect', url))

    for tag in get_html.find_all('a', href=True):
        href = _clean_url(tag['href'])
        if href.startswith('http'):
            found.append(('anchor href', href))
        onclick = tag.get('onclick', '')
        if onclick:
            for m in re.finditer(r'location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', onclick):
                found.append(('onclick redirect', _clean_url(m.group(1))))

    for tag in get_html.find_all('form', action=True):
        action = _clean_url(tag['action'])
        if action.startswith('http'):
            found.append(('form action', action))

    for tag in get_html.find_all('meta'):
        if tag.get('http-equiv', '').lower() == 'refresh':
            content_val = tag.get('content', '')
            m = re.search(r'url=([^\s;]+)', content_val, re.IGNORECASE)
            s = re.search(r'^(\d+)', content_val)
            if m:
                found.append((f'meta refresh ({s.group(1) if s else "?"}s)', _clean_url(m.group(1))))

    for tag in get_html.find_all('iframe', src=True):
        src = _clean_url(tag['src'])
        if src.startswith('http'):
            found.append(('iframe src', src))

    qp = re.sub(r'=\n', '', quopri.decodestring(raw_content.encode()).decode('utf-8', errors='replace') if raw_content else '')
    qp = qp.replace('=3D', '=').replace('=3d', '=')
    for m in re.finditer(r'href\s*=\s*["\']?(https?://[^\s"\'<>]+)', qp, re.IGNORECASE):
        found.append(('QP decoded href', _clean_url(m.group(1))))

    for m in re.finditer(r'<(https?://[^\s>]+)>', raw_content):
        found.append(('plain text URL', _clean_url(m.group(1))))

    for m in re.finditer(r'(?<!\w)(https?://[^\s<>"\')\]]{10,})', raw_content):
        found.append(('body URL', _clean_url(m.group(1))))

    unique = []
    seen = set()
    for label, url in found:
        key = _url_key(url)
        if key not in seen and len(url) > 8:
            seen.add(key)
            unique.append((label, url))

    return unique


def _scan_html_for_urls(html_text, source_label="file"):
    print(Colors.bold(f"\n[+] Scanning {source_label} for IOCs..."))

    title = re.search(r'<title[^>]*>([^<]+)</title>', html_text, re.IGNORECASE)
    if title:
        print(Colors.cyan(f"  [*] Page title: {title.group(1).strip()}"))

    for pattern, label in PHISHING_PATTERNS:
        if re.search(pattern, html_text, re.IGNORECASE):
            print(Colors.red(f"  [!] {label}"))

    obf = []
    if 'eval('             in html_text: obf.append('eval()')
    if 'atob('             in html_text: obf.append('atob()')
    if 'String.fromCharCode' in html_text: obf.append('String.fromCharCode()')
    if 'unescape('         in html_text: obf.append('unescape()')
    if obf:
        print(Colors.orange(f"  [!] JS obfuscation: {', '.join(obf)}"))

    JS_PATTERNS = [
        (r'window\.location(?:\.href)?\s*=\s*["\']([^"\']{8,})["\']',   "window.location"),
        (r'location\.(?:replace|assign)\s*\(\s*["\']([^"\']{8,})["\']',  "location.replace/assign"),
        (r'<meta[^>]+refresh[^>]+url=([^\s"\']{8,})',                     "meta refresh"),
        (r'(?:redirect|destination|return_url|next|goto)\s*[=:]\s*["\']?(https?://[^"\'<>\s&]{8,})', "redirect param"),
        (r'atob\(["\']([A-Za-z0-9+/=]{20,})["\']',                       "atob() encoded"),
    ]

    js_hits = []
    seen_js = set()
    for pat, lbl in JS_PATTERNS:
        for m in re.finditer(pat, html_text, re.IGNORECASE | re.DOTALL):
            val = m.group(1).strip().rstrip(".,;)'\">/")
            if lbl == "atob() encoded":
                try:
                    val = f"{val} => {base64.b64decode(val + '==').decode('utf-8', errors='replace')}"
                except Exception:
                    pass
            if val not in seen_js:
                seen_js.add(val)
                js_hits.append((lbl, val))

    if js_hits:
        print(Colors.bold(f"  [+] JS redirect / encoded values ({len(js_hits)}):"))
        for lbl, val in js_hits:
            print(Colors.red(f"      [{lbl}] {val}"))

    all_urls = list(dict.fromkeys(
        u.rstrip(".,;)'\">/")
        for u in re.findall(r'https?://[^\s"\'<>\]\[()]+', html_text)
    ))
    external = [u for u in all_urls if not any(n in u for n in NOISE_DOMAINS)]

    forms = re.findall(r'<form[^>]+action=["\']?([^"\'>\s]+)', html_text, re.IGNORECASE)
    if forms:
        print(Colors.orange("  [!] Form actions:"))
        for fm in set(forms):
            print(Colors.orange(f"      -> {fm}"))

    hidden = re.findall(
        r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
        html_text, re.IGNORECASE
    )
    if hidden:
        print(Colors.yellow("  [*] Hidden inputs:"))
        for name, val in hidden[:8]:
            print(Colors.yellow(f"      {name} = {val[:100]}"))

    ext_scripts = [
        s for s in re.findall(r'<script[^>]+src=["\']?(https?://[^"\'<>\s]+)', html_text, re.IGNORECASE)
        if not any(n in s for n in NOISE_DOMAINS)
    ]
    if ext_scripts:
        print(Colors.orange(f"  [!] External scripts ({len(ext_scripts)}):"))
        for s in ext_scripts:
            print(Colors.orange(f"      {s}"))

    if external:
        print(Colors.bold(f"  [+] All external URLs ({len(external)}):"))
        for u in external:
            flag = f" <-- {_is_suspicious_ext(u)}" if _is_suspicious_ext(u) else ""
            print(Colors.red(f"      {u}{flag}"))
    else:
        print(Colors.yellow("  [!] No external URLs found in response"))


def _follow_redirect_chain(url):
    print(Colors.yellow(f"\n[*] Following: {url}"))
    session = requests.Session()
    session.max_redirects = 15

    # Step 1: HEAD — catch immediate Location header
    try:
        r = session.head(url, headers=BROWSER_HEADERS, timeout=8, verify=False, allow_redirects=False)
        loc = r.headers.get("Location")
        if loc:
            print(Colors.green(f"  [+] HEAD Location: {loc}"))
    except Exception:
        pass

    # Step 2: GET — follow full chain
    try:
        resp = session.get(url, headers=BROWSER_HEADERS, timeout=15, verify=False, allow_redirects=True)
        chain = [r.url for r in resp.history] + [resp.url]

        print(Colors.cyan(f"  HTTP chain ({len(chain)} hop{'s' if len(chain)>1 else ''}):"))
        for i, hop in enumerate(chain):
            marker = " <-- FINAL" if i == len(chain) - 1 else ""
            print(Colors.cyan(f"    {i+1}. {hop}{marker}"))
        print(Colors.cyan(f"  Status: {resp.status_code} | Server: {resp.headers.get('Server','?')}"))

        loc_hdr = resp.headers.get("Location") or resp.headers.get("Refresh")
        if loc_hdr:
            print(Colors.orange(f"  [!] Location/Refresh header: {loc_hdr}"))

        _scan_html_for_urls(resp.text, "response body")

        # Step 3: urlscan.io passive lookup (no key needed)
        domain = urlparse(resp.url).netloc
        print(Colors.cyan(f"\n[*] Checking urlscan.io for existing scans of {domain}..."))
        try:
            sr = requests.get(
                f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=3",
                headers={"User-Agent": "ThreatIntel/1.0"}, timeout=8
            )
            if sr.status_code == 200:
                results = sr.json().get("results", [])
                if results:
                    print(Colors.green(f"  [+] urlscan.io — {len(results)} scan(s) found:"))
                    for res in results[:3]:
                        final_u = res.get("page", {}).get("url", "N/A")
                        scan_id = res.get("_id", "")
                        print(Colors.cyan(f"    Final URL : {final_u}"))
                        print(Colors.cyan(f"    Report    : https://urlscan.io/result/{scan_id}/"))
                        if final_u and final_u != url:
                            print(Colors.red(f"    [!] REDIRECTED TO: {final_u}"))
                else:
                    print(Colors.yellow(f"  [!] No scans found. Submit: https://urlscan.io/scan/#{url}"))
        except Exception as e:
            print(Colors.yellow(f"  [!] urlscan.io query failed: {e}"))

        print(Colors.bold("\n[+] Suggestions if destination still unclear:"))
        print(Colors.yellow(f"  1. urlscan.io  : https://urlscan.io/search/#page.domain:{domain}"))
        print(Colors.yellow(f"  2. VirusTotal  : https://www.virustotal.com/gui/home/url"))
        print(Colors.yellow(f"  3. ANY.RUN     : https://app.any.run"))
        print(Colors.yellow(f"  4. curl -v -L --max-redirs 20 -A 'Mozilla/5.0' '{url}' 2>&1 | grep -i location"))
        print(Colors.yellow(f"  5. Wayback     : https://web.archive.org/web/*/{url}"))

    except requests.exceptions.TooManyRedirects:
        print(Colors.red("  [!] Too many redirects."))
    except requests.exceptions.ConnectionError as e:
        print(Colors.red(f"  [!] Connection error: {e}"))
    except requests.exceptions.Timeout:
        print(Colors.red("  [!] Timed out."))
    except Exception as e:
        print(Colors.red(f"  [!] Failed: {e}"))


def _download_payload(url):
    print(Colors.yellow(f"\n[*] Attempting to fetch: {url}"))
    print(Colors.red("[!] WARNING: potentially malicious URL."))
    if input(Colors.red("    Type 'YES' to confirm: ")).strip() != 'YES':
        print(Colors.yellow("[*] Cancelled."))
        return

    save_dir = Path.cwd() / 'payloads'
    save_dir.mkdir(exist_ok=True)

    try:
        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(url, headers=BROWSER_HEADERS, timeout=15,
                           verify=False, allow_redirects=True, stream=True)

        if resp.url != url:
            print(Colors.orange(f"  [!] Followed redirect to: {resp.url}"))

        content_type = resp.headers.get('Content-Type', 'unknown')
        print(Colors.cyan(f"  [*] Status       : {resp.status_code}"))
        print(Colors.cyan(f"  [*] Content-Type : {content_type}"))
        print(Colors.cyan(f"  [*] Server       : {resp.headers.get('Server', '?')}"))

        ext_map = {'html': '.html', 'pdf': '.pdf', 'zip': '.zip', 'octet-stream': '.bin'}
        ext = next((v for k, v in ext_map.items() if k in content_type.lower()), '.bin')

        parsed = urlparse(url)
        filename = Path(parsed.path).name or 'payload'
        filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
        if not filename.endswith(ext):
            filename += ext

        save_path = save_dir / filename
        with open(save_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        size = save_path.stat().st_size
        print(Colors.green(f"  [+] Saved: {save_path}  ({size} bytes)"))
        print(Colors.red("  [!] DO NOT execute outside a sandbox."))

        if susp := _is_suspicious_ext(str(save_path)):
            print(Colors.red(f"  [!] Suspicious extension: {susp}"))

        if 'html' in content_type.lower() or save_path.suffix == '.html':
            with open(save_path, 'r', encoding='utf-8', errors='replace') as fh:
                _scan_html_for_urls(fh.read(), str(save_path))

    except requests.exceptions.TooManyRedirects:
        print(Colors.red("  [!] Too many redirects."))
    except requests.exceptions.SSLError:
        print(Colors.red("  [!] SSL error."))
    except requests.exceptions.ConnectionError:
        print(Colors.red("  [!] Connection refused."))
    except requests.exceptions.Timeout:
        print(Colors.red("  [!] Timed out."))
    except Exception as e:
        print(Colors.red(f"  [!] Failed: {e}"))


def expandURL(url):
    load_dotenv()
    TOKEN_EXPANDER = os.getenv("TOKEN_EXPANDER")
    if not TOKEN_EXPANDER:
        print(Colors.yellow("[!] TOKEN_EXPANDER not set in .env"))
        sys.exit(1)
    res = requests.post(
        "https://onesimpleapi.com/api/unshorten",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN_EXPANDER}"},
        json={"output": "json"}
    )
    return res.json() if res.ok else None


def _handle_found_url(url, label):
    print(Colors.red(f"\n  [{label}]"))
    print(Colors.red(f"  {url}"))

    is_short = next((s for s in URL_SHORTENERS_LIST if s in url), None)
    if is_short:
        print(Colors.yellow(f"  [!] URL shortener detected ({is_short})"))
        if input(Colors.yellow("      Expand? (yes/no): ")).strip().lower() == 'yes':
            expanded = expandURL(url)
            if expanded:
                print(Colors.cyan(f"      Expanded: {expanded}"))
                url = expanded if isinstance(expanded, str) else url

    decoded = unquote(url)
    if decoded != url:
        print(Colors.orange(f"  [!] URL-encoded — decoded: {decoded}"))
        url = decoded

    if susp := _is_suspicious_ext(url):
        print(Colors.red(f"  [!] Suspicious extension: {susp}"))

    action = input(Colors.yellow("  [f]ollow redirects / [d]ownload payload / [s]kip: ")).strip().lower()
    if action == 'f':
        _follow_redirect_chain(url)
    elif action == 'd':
        _download_payload(url)


def javascript_ioc(file):
    eml_path = _resolve_eml(file)

    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    if not content.strip():
        print(Colors.red("[!] File is empty."))
        return

    get_html = bs4.BeautifulSoup(content, 'html.parser')
    all_redirect_urls = []

    for p in get_html.find_all('script'):
        script_text = p.text.strip()
        if not script_text:
            continue

        if 'atob(' in script_text:
            print(Colors.orange("[!] atob() found — Base64 encoded content"))
            for match in re.findall(r"atob\(['\"]([^'\"]+)['\"]\)", script_text):
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='replace')
                    print(Colors.yellow(f"[*] atob decoded: {decoded}"))
                    if decoded.startswith('http'):
                        all_redirect_urls.append(('atob() decoded URL', decoded))
                except Exception:
                    pass

        if 'eval(' in script_text:
            print(Colors.red("[!] eval() found — possible code execution"))
            m = re.search(r'eval\((.*?)\)', script_text, re.DOTALL)
            if m:
                print(Colors.orange(f"    eval contents: {m.group(1)[:120]}"))

        if 'String.fromCharCode' in script_text:
            print(Colors.orange("[!] String.fromCharCode() — char-code obfuscation"))
            for cc in re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', script_text):
                try:
                    chars = ''.join(chr(int(c.strip())) for c in cc.split(',') if c.strip())
                    print(Colors.yellow(f"    decoded: {chars}"))
                except Exception:
                    pass

        if 'unescape(' in script_text or 'decodeURIComponent(' in script_text:
            print(Colors.orange("[!] unescape/decodeURIComponent — URL obfuscation"))

        if 'setTimeout' in script_text:
            m = re.search(
                r'setTimeout\s*\(.*?(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\'].*?(\d+)\s*\)',
                script_text, re.DOTALL
            )
            if m:
                redir_url = m.group(1)
                delay     = int(m.group(2)) / 1000
                print(Colors.orange(f"[!] setTimeout redirect after {delay}s -> {redir_url}"))
                all_redirect_urls.append((f'setTimeout ({delay}s)', redir_url))

        for label, url in _collect_all_redirects(script_text, content, get_html):
            if url not in [u for _, u in all_redirect_urls]:
                all_redirect_urls.append((label, url))

    for meta in get_html.find_all('meta'):
        if meta.get('http-equiv', '').lower() == 'refresh':
            content_val = meta.get('content', '')
            url_m = re.search(r'url=([^\s;]+)', content_val, re.IGNORECASE)
            sec_m = re.search(r'^(\d+)', content_val)
            if url_m:
                redir = _clean_url(url_m.group(1))
                delay = sec_m.group(1) if sec_m else '?'
                print(Colors.yellow(f"[*] Meta refresh -> {redir} (after {delay}s)"))
                is_short = next((s for s in URL_SHORTENERS_LIST if s in redir), None)
                if is_short:
                    print(Colors.yellow(f"[*] Uses URL shortener ({is_short})"))
                    if input("    Expand? (yes/no): ").strip().lower() == 'yes':
                        print(expandURL(redir))

    for label, url in _collect_all_redirects('', content, get_html):
        if url not in [u for _, u in all_redirect_urls]:
            all_redirect_urls.append((label, url))

    if all_redirect_urls:
        print(Colors.bold(f"\n[+] === URLS / REDIRECTS FOUND — Total: {len(all_redirect_urls)} ==="))
        print("─" * 60)
        for label, url in all_redirect_urls:
            print(Colors.orange(f"  [{label}]"))
            print(Colors.red(f"    {url}"))
        print("─" * 60)

        print(Colors.yellow("\n[*] Review each URL:"))
        for label, url in all_redirect_urls:
            _handle_found_url(url, label)
    else:
        print(Colors.green("[+] No URLs or redirects detected."))
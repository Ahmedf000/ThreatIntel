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

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Constants ────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.ly", "rebrand.ly", "is.gd", "goo.su",
    "qrco.de", "clck.ru", "cutt.ly", "rb.gy", "dub.sh", "short.io",
    "ow.ly", "tiny.cc", "spoo.me", "kutt.it", "buff.ly", "bitly.com",
    "shorte.st", "adf.ly", "u.to", "git.io", "t.co", "fb.me", "t.me",
    "shortcm.li", "tny.im", "chilp.it", "y2u.be", "shorturl.at",
}

SUSPICIOUS_EXTS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.jar', '.scr',
    '.hta', '.msi', '.iso', '.lnk', '.wsf', '.sh', '.docm', '.xlsm',
    '.js', '.jse', '.vbe', '.pif', '.reg', '.cpl',
]

NOISE_DOMAINS = [
    "jquery", "bootstrap", "googleapis", "gstatic", "w3.org",
    "schema.org", "facebook.net", "cdn.jsdelivr", "unpkg.com", "cdnjs",
]

PHISHING_PATTERNS = [
    (r"\blogin\b",                                      "Login form detected"),
    (r"\bpassword\b",                                   "Password field detected"),
    (r"\bcredential",                                   "Credential harvesting indicator"),
    (r"\bsignin\b|sign[- ]in",                          "Sign-in form detected"),
    (r"\bverif",                                        "Verification page detected"),
    (r"update.*payment|payment.*update",                "Payment update page"),
    (r"paypal",                                         "PayPal impersonation possible"),
    (r"microsoft|office\s?365|outlook",                 "Microsoft impersonation possible"),
    (r"google|gmail",                                   "Google impersonation possible"),
    (r"apple\.com|icloud",                              "Apple impersonation possible"),
    (r"amazon",                                         "Amazon impersonation possible"),
    (r"bankofamerica|wellsfargo|chase|hsbc|barclays",   "Banking impersonation possible"),
    (r"docusign|dropbox|sharepoint",                    "Cloud service impersonation possible"),
    (r"account.*suspend|suspend.*account",              "Account suspension threat"),
    (r"urgent|immediate.{0,20}action",                  "Urgency language detected"),
]

BROWSER_HEADERS = {
    "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                 "AppleWebKit/537.36 (KHTML, like Gecko) "
                                 "Chrome/124.0.0.0 Safari/537.36",
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control":             "max-age=0",
}

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


# ── Path resolver ─────────────────────────────────────────────────
def _resolve_eml(file: str) -> str:
    candidate = os.path.expanduser(str(file).strip())
    if candidate.endswith('.eml'):
        candidate = candidate[:-4]

    def _try(p: Path) -> Path | None:
        full = Path(str(p) + '.eml')
        return full if full.exists() else None

    for base in [
        Path(candidate),
        Path.cwd() / Path(candidate).name,
        Path.home() / 'Desktop' / Path(candidate).name,
        Path('/root/Desktop') / Path(candidate).name,
    ]:
        found = _try(base)
        if found:
            return str(found)

    raise FileNotFoundError(
        f"[!] Could not find '{Path(candidate).name}.eml'"
    )


# ── URL helpers ───────────────────────────────────────────────────
def _clean_url(url: str) -> str:
    url = url.strip().rstrip(".,;)'\">/")
    url = re.sub(r'=\n', '', url)
    url = url.replace('=3D', '=').replace('=3d', '=')
    url = re.sub(r'\s+', '', url)
    return unquote(url)


def _url_key(u: str) -> str:
    """Canonical key for deduplication — strips query params."""
    return re.sub(r'[?&][^=]+=\S*', '', u).rstrip('?&')


def _is_suspicious_ext(url: str) -> str | None:
    path = urlparse(url).path.lower()
    return next((e for e in SUSPICIOUS_EXTS if path.endswith(e)), None)


def _is_shortener(url: str) -> str | None:
    return next((s for s in URL_SHORTENERS if s in url), None)


# ── URL expander (fixed: now sends the url field) ─────────────────
def expand_url(url: str) -> str | None:
    token = os.getenv("TOKEN_EXPANDER")
    if not token:
        print(Colors.yellow("  [!] TOKEN_EXPANDER not set in .env — cannot expand."))
        return None
    try:
        res = requests.post(
            "https://onesimpleapi.com/api/unshorten",
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {token}",
            },
            # FIX: original sent {"output":"json"} with NO url field
            json={"url": url, "output": "json"},
            timeout=10,
        )
        if res.ok:
            data = res.json()
            # API returns {"result": "https://..."} or plain string
            expanded = data.get("result") or data.get("url") or (data if isinstance(data, str) else None)
            return str(expanded) if expanded else None
        else:
            print(Colors.yellow(f"  [!] Expander returned HTTP {res.status_code}"))
            return None
    except Exception as e:
        print(Colors.red(f"  [!] expand_url error: {e}"))
        return None


# ── Collect all redirect / URL sources from parsed HTML ──────────
def _collect_all_redirects(
        script_text: str,
        raw_content: str,
        soup: BeautifulSoup,
) -> list[tuple[str, str]]:
    """
    Returns a deduplicated list of (label, url) from every source:
    JS redirect patterns, anchor hrefs, form actions, meta refresh,
    iframes, QP-decoded hrefs, plain-text body URLs.
    """
    found: list[tuple[str, str]] = []

    # JS patterns in script text
    if script_text:
        for pat in JS_REDIRECT_PATTERNS:
            for m in re.finditer(pat, script_text, re.IGNORECASE | re.DOTALL):
                url = _clean_url(m.group(1))
                if url.startswith('http'):
                    found.append(('JS redirect', url))

    # <a href>
    for tag in soup.find_all('a', href=True):
        href = _clean_url(tag['href'])
        if href.startswith('http'):
            found.append(('anchor href', href))
        onclick = tag.get('onclick', '')
        if onclick:
            for m in re.finditer(r'location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', onclick):
                found.append(('onclick redirect', _clean_url(m.group(1))))

    # <form action>
    for tag in soup.find_all('form', action=True):
        action = _clean_url(tag['action'])
        if action.startswith('http'):
            found.append(('form action', action))

    # <meta http-equiv="refresh">
    for tag in soup.find_all('meta'):
        if tag.get('http-equiv', '').lower() == 'refresh':
            content_val = tag.get('content', '')
            m = re.search(r'url=([^\s;]+)', content_val, re.IGNORECASE)
            s = re.search(r'^(\d+)', content_val)
            if m:
                found.append((
                    f'meta refresh ({s.group(1) if s else "?"}s)',
                    _clean_url(m.group(1))
                ))

    # <iframe src>
    for tag in soup.find_all('iframe', src=True):
        src = _clean_url(tag['src'])
        if src.startswith('http'):
            found.append(('iframe src', src))

    # QP-decoded hrefs
    try:
        qp = quopri.decodestring(raw_content.encode()).decode('utf-8', errors='replace')
        qp = re.sub(r'=\n', '', qp).replace('=3D', '=').replace('=3d', '=')
        for m in re.finditer(r'href\s*=\s*["\']?(https?://[^\s"\'<>]+)', qp, re.IGNORECASE):
            found.append(('QP decoded href', _clean_url(m.group(1))))
    except Exception:
        pass

    # Plain <URL> in angle brackets
    for m in re.finditer(r'<(https?://[^\s>]+)>', raw_content):
        found.append(('plain text URL', _clean_url(m.group(1))))

    # Bare body URLs
    for m in re.finditer(r'(?<!\w)(https?://[^\s<>"\')\]]{10,})', raw_content):
        found.append(('body URL', _clean_url(m.group(1))))

    # Deduplicate
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, url in found:
        key = _url_key(url)
        if key not in seen and len(url) > 8:
            seen.add(key)
            unique.append((label, url))

    return unique


# ── Scan HTML response for IOCs ───────────────────────────────────
def _scan_html_for_urls(html_text: str, source_label: str = "page"):
    print(Colors.bold(f"\n  [+] Scanning {source_label} for IOCs..."))

    title = re.search(r'<title[^>]*>([^<]+)</title>', html_text, re.IGNORECASE)
    if title:
        print(Colors.cyan(f"    [*] Page title: {title.group(1).strip()}"))

    for pattern, label in PHISHING_PATTERNS:
        if re.search(pattern, html_text, re.IGNORECASE):
            print(Colors.red(f"    [!] {label}"))

    obf = []
    for marker, name in [
        ('eval(',             'eval()'),
        ('atob(',             'atob()'),
        ('String.fromCharCode', 'String.fromCharCode()'),
        ('unescape(',         'unescape()'),
        ('document.write(',   'document.write()'),
    ]:
        if marker in html_text:
            obf.append(name)
    if obf:
        print(Colors.orange(f"    [!] JS obfuscation: {', '.join(obf)}"))

    forms = re.findall(r'<form[^>]+action=["\']?([^"\'>\s]+)', html_text, re.IGNORECASE)
    if forms:
        print(Colors.orange("    [!] Form action(s):"))
        for fm in set(forms):
            print(Colors.orange(f"        → {fm}"))

    ext_scripts = [
        s for s in re.findall(
            r'<script[^>]+src=["\']?(https?://[^"\'<>\s]+)', html_text, re.IGNORECASE
        )
        if not any(n in s for n in NOISE_DOMAINS)
    ]
    if ext_scripts:
        print(Colors.orange(f"    [!] External scripts ({len(ext_scripts)}):"))
        for s in ext_scripts:
            print(Colors.orange(f"        {s}"))

    all_urls = list(dict.fromkeys(
        u.rstrip(".,;)'\">/")
        for u in re.findall(r'https?://[^\s"\'<>\]\[()]+', html_text)
    ))
    external = [u for u in all_urls if not any(n in u for n in NOISE_DOMAINS)]
    if external:
        print(Colors.bold(f"    [+] External URLs found ({len(external)}):"))
        for u in external:
            flag = f"  ← SUSPICIOUS EXT: {_is_suspicious_ext(u)}" if _is_suspicious_ext(u) else ""
            short = f"  ← SHORTENER: {_is_shortener(u)}" if _is_shortener(u) else ""
            print(Colors.red(f"        {u}{flag}{short}"))


# ── Follow redirect chain ─────────────────────────────────────────
def _follow_redirect_chain(url: str):
    print(Colors.yellow(f"\n  [*] Following redirect chain for: {url}"))
    session = requests.Session()
    session.max_redirects = 20

    # HEAD first — catches immediate 301/302 Location header
    try:
        r = session.head(url, headers=BROWSER_HEADERS, timeout=8,
                         verify=False, allow_redirects=False)
        loc = r.headers.get("Location")
        if loc:
            print(Colors.green(f"  [→] HEAD Location header: {loc}"))
    except Exception:
        pass

    # Full GET — follows all HTTP-level redirects
    try:
        resp = session.get(url, headers=BROWSER_HEADERS, timeout=20,
                           verify=False, allow_redirects=True)
    except requests.exceptions.TooManyRedirects:
        print(Colors.red("  [!] Too many redirects (>20). Aborting."))
        return
    except requests.exceptions.ConnectionError as e:
        print(Colors.red(f"  [!] Connection error: {e}"))
        return
    except requests.exceptions.Timeout:
        print(Colors.red("  [!] Request timed out."))
        return
    except Exception as e:
        print(Colors.red(f"  [!] Unexpected error: {e}"))
        return

    # Print HTTP hop chain
    chain = [r.url for r in resp.history] + [resp.url]
    print(Colors.cyan(f"\n  HTTP redirect chain ({len(chain)} hop{'s' if len(chain) > 1 else ''}):"))
    for i, hop in enumerate(chain):
        marker = "  ← FINAL DESTINATION" if i == len(chain) - 1 else ""
        print(Colors.cyan(f"    {i+1}. {hop}{marker}"))
    print(Colors.cyan(f"  Status: {resp.status_code}  |  Server: {resp.headers.get('Server', 'unknown')}"))

    # Check for Location/Refresh header on final response
    loc_hdr = resp.headers.get("Location") or resp.headers.get("Refresh")
    if loc_hdr:
        print(Colors.orange(f"  [!] Final response still has Location/Refresh: {loc_hdr}"))

    # Scan the HTML body for IOCs
    _scan_html_for_urls(resp.text, "final page body")

    # ── NEW: extract JS/meta redirects from the fetched page ─────
    soup = BeautifulSoup(resp.text, 'html.parser')
    page_urls = _collect_all_redirects('', resp.text, soup)
    # Filter to only redirects not already shown in chain
    chain_urls = set(chain)
    secondary = [(lbl, u) for lbl, u in page_urls if u not in chain_urls]
    if secondary:
        print(Colors.bold(f"\n  [+] JS/HTML redirects found inside the fetched page ({len(secondary)}):"))
        print("  " + "─" * 56)
        for lbl, u in secondary:
            print(Colors.orange(f"    [{lbl}] {u}"))
        print("  " + "─" * 56)
        for lbl, u in secondary:
            _handle_found_url(u, f"page-embedded {lbl}")

    # urlscan.io passive lookup
    domain = urlparse(resp.url).netloc
    print(Colors.cyan(f"\n  [*] Checking urlscan.io for existing scans of {domain}…"))
    try:
        sr = requests.get(
            f"https://urlscan.io/api/v1/search/?q=page.domain:{domain}&size=3",
            headers={"User-Agent": "ThreatIntel/1.0"}, timeout=8
        )
        if sr.status_code == 200:
            results = sr.json().get("results", [])
            if results:
                print(Colors.green(f"  [+] urlscan.io — {len(results)} existing scan(s):"))
                for res in results[:3]:
                    final_u = res.get("page", {}).get("url", "N/A")
                    scan_id = res.get("_id", "")
                    print(Colors.cyan(f"      Final URL : {final_u}"))
                    print(Colors.cyan(f"      Report    : https://urlscan.io/result/{scan_id}/"))
                    if final_u and final_u != url:
                        print(Colors.red(f"      [!] Redirected to: {final_u}"))
            else:
                print(Colors.yellow(f"  [!] No existing scans. Submit manually:"))
                print(Colors.yellow(f"      https://urlscan.io/scan/#{url}"))
    except Exception as e:
        print(Colors.yellow(f"  [!] urlscan.io query failed: {e}"))

    print(Colors.bold("\n  [+] Further investigation tools:"))
    print(Colors.yellow(f"    1. urlscan.io  → https://urlscan.io/search/#page.domain:{domain}"))
    print(Colors.yellow(f"    2. VirusTotal  → https://www.virustotal.com/gui/home/url"))
    print(Colors.yellow(f"    3. ANY.RUN     → https://app.any.run"))
    print(Colors.yellow(f"    4. Wayback     → https://web.archive.org/web/*/{url}"))
    print(Colors.yellow(f"    5. curl cmd    → curl -v -L --max-redirs 20 -A 'Mozilla/5.0' '{url}' 2>&1 | grep -i location"))


# ── Download payload ──────────────────────────────────────────────
def _download_payload(url: str):
    print(Colors.yellow(f"\n  [*] Attempting payload download: {url}"))
    print(Colors.red("  [!!!] WARNING: This may be a malicious file."))
    confirm = input(Colors.red("        Type YES to confirm download: ")).strip()
    if confirm != 'YES':
        print(Colors.yellow("  [*] Download cancelled."))
        return

    # Save to Desktop/payloads/ so it's actually findable
    desktop_candidates = [
        Path.home() / 'Desktop' / 'payloads',
        Path('/root/Desktop') / 'payloads',
        Path.cwd() / 'payloads',
    ]
    save_dir = next(
        (d.parent for d in desktop_candidates if d.parent.exists()),
        Path.cwd()
    ) / 'payloads'
    save_dir.mkdir(parents=True, exist_ok=True)

    try:
        session = requests.Session()
        session.max_redirects = 15
        resp = session.get(url, headers=BROWSER_HEADERS, timeout=20,
                           verify=False, allow_redirects=True, stream=True)

        if resp.url != url:
            print(Colors.orange(f"  [!] Followed redirect to: {resp.url}"))

        content_type = resp.headers.get('Content-Type', 'application/octet-stream')
        print(Colors.cyan(f"  Status       : {resp.status_code}"))
        print(Colors.cyan(f"  Content-Type : {content_type}"))
        print(Colors.cyan(f"  Server       : {resp.headers.get('Server', 'unknown')}"))
        print(Colors.cyan(f"  Content-Length: {resp.headers.get('Content-Length', 'unknown')}"))

        ext_map = {
            'html': '.html', 'pdf': '.pdf', 'zip': '.zip',
            'octet-stream': '.bin', 'msword': '.doc',
            'vnd.openxmlformats': '.docx', 'javascript': '.js',
            'x-sh': '.sh', 'x-php': '.php', 'plain': '.txt',
            'x-executable': '.bin', 'x-msdos-program': '.exe',
        }
        ext = next((v for k, v in ext_map.items() if k in content_type.lower()), '.bin')

        parsed = urlparse(resp.url)
        filename = Path(parsed.path).name or 'payload'
        filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
        if not any(filename.endswith(e) for e in SUSPICIOUS_EXTS + ['.html', '.pdf', '.zip', '.bin', '.txt']):
            filename += ext

        save_path = save_dir / filename
        total = 0
        with open(save_path, 'wb') as fh:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    fh.write(chunk)
                    total += len(chunk)

        print(Colors.green(f"\n  [+] Saved to: {save_path}  ({total:,} bytes)"))
        print(Colors.red("  [!!!] DO NOT execute this file outside an isolated sandbox."))

        if susp := _is_suspicious_ext(str(save_path)):
            print(Colors.red(f"  [!] Suspicious extension detected: {susp}"))

        if 'html' in content_type.lower() or save_path.suffix == '.html':
            print(Colors.yellow("  [*] HTML payload — scanning for embedded IOCs…"))
            with open(save_path, 'r', encoding='utf-8', errors='replace') as fh:
                _scan_html_for_urls(fh.read(), str(save_path))

    except requests.exceptions.TooManyRedirects:
        print(Colors.red("  [!] Too many redirects."))
    except requests.exceptions.SSLError as e:
        print(Colors.red(f"  [!] SSL error: {e}"))
    except requests.exceptions.ConnectionError as e:
        print(Colors.red(f"  [!] Connection refused: {e}"))
    except requests.exceptions.Timeout:
        print(Colors.red("  [!] Request timed out."))
    except Exception as e:
        print(Colors.red(f"  [!] Download failed: {e}"))


# ── Per-URL interactive handler ───────────────────────────────────
def _handle_found_url(url: str, label: str):
    print(Colors.bold(f"\n  ┌─ [{label}]"))
    print(Colors.red(f"  │  {url}"))

    short = _is_shortener(url)
    if short:
        print(Colors.yellow(f"  │  [!] URL shortener detected: {short}"))
        expand_q = input(Colors.yellow("  │  Expand this short URL? (yes/no): ")).strip().lower()
        if expand_q == 'yes':
            expanded = expand_url(url)
            if expanded and expanded != url:
                print(Colors.cyan(f"  │  Expanded → {expanded}"))
                url = expanded
            else:
                print(Colors.yellow("  │  Could not expand."))

    decoded = unquote(url)
    if decoded != url:
        print(Colors.orange(f"  │  [!] URL-encoded — decoded: {decoded}"))
        url = decoded

    if susp := _is_suspicious_ext(url):
        print(Colors.red(f"  │  [!] Suspicious extension: {susp}"))

    print(Colors.yellow("  └─ Action: [f]ollow redirects / [d]ownload payload / [s]kip: "), end='')
    action = input().strip().lower()
    if action == 'f':
        _follow_redirect_chain(url)
    elif action == 'd':
        _download_payload(url)
    else:
        print(Colors.yellow("  [*] Skipped."))


# ── Main entry point ──────────────────────────────────────────────
def javascript_ioc(file: str):
    eml_path = _resolve_eml(file)

    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    if not content.strip():
        print(Colors.red("[!] File is empty."))
        return

    print(Colors.bold("\n╔══════════════════════════════════════════════════════════╗"))
    print(Colors.bold("║           JAVASCRIPT / HTML IOC ANALYSIS                 ║"))
    print(Colors.bold("╚══════════════════════════════════════════════════════════╝"))

    soup = BeautifulSoup(content, 'html.parser')
    collected: list[tuple[str, str]] = []
    seen_keys: set[str] = set()

    def _add(label: str, url: str):
        k = _url_key(url)
        if k not in seen_keys and len(url) > 8:
            seen_keys.add(k)
            collected.append((label, url))

    # ── Per-script analysis ───────────────────────────────────────
    for idx, script_tag in enumerate(soup.find_all('script'), start=1):
        script_text = script_tag.get_text()
        if not script_text.strip():
            continue

        print(Colors.bold(f"\n[+] Script block #{idx}"))
        print("─" * 60)

        # atob() base64
        if 'atob(' in script_text:
            print(Colors.orange("  [!] atob() found — Base64 encoded content:"))
            for b64 in re.findall(r"atob\(['\"]([^'\"]+)['\"]\)", script_text):
                try:
                    decoded = base64.b64decode(b64 + '==').decode('utf-8', errors='replace')
                    print(Colors.yellow(f"      {b64}"))
                    print(Colors.cyan( f"    → {decoded}"))
                    if decoded.startswith('http'):
                        _add('atob() decoded URL', decoded)
                except Exception:
                    pass

        # eval()
        if 'eval(' in script_text:
            print(Colors.red("  [!] eval() found — possible dynamic code execution"))
            m = re.search(r'eval\((.*?)\)', script_text, re.DOTALL)
            if m:
                print(Colors.orange(f"      eval argument: {m.group(1)[:200]}"))

        # String.fromCharCode
        if 'String.fromCharCode' in script_text:
            print(Colors.orange("  [!] String.fromCharCode() — character-code obfuscation"))
            for cc in re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', script_text):
                try:
                    decoded = ''.join(chr(int(c.strip())) for c in cc.split(',') if c.strip())
                    print(Colors.yellow(f"      decoded: {decoded[:200]}"))
                    if decoded.startswith('http'):
                        _add('fromCharCode decoded URL', decoded)
                except Exception:
                    pass

        # unescape / decodeURIComponent
        if 'unescape(' in script_text or 'decodeURIComponent(' in script_text:
            print(Colors.orange("  [!] unescape/decodeURIComponent — URL obfuscation"))

        # setTimeout redirect
        if 'setTimeout' in script_text:
            m = re.search(
                r'setTimeout\s*\(.*?(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\'].*?(\d+)\s*\)',
                script_text, re.DOTALL
            )
            if m:
                redir_url = m.group(1)
                delay     = int(m.group(2)) / 1000
                print(Colors.orange(f"  [!] setTimeout redirect after {delay}s → {redir_url}"))
                _add(f'setTimeout ({delay}s)', redir_url)

        # Collect everything else from this script + HTML context
        # NOTE: called ONCE here per script block — NOT again after the loop
        for lbl, url in _collect_all_redirects(script_text, content, soup):
            _add(lbl, url)

    # ── Meta refresh (outside scripts) ───────────────────────────
    print(Colors.bold("\n[+] Meta Tag Analysis"))
    print("─" * 60)
    found_meta = False
    for meta in soup.find_all('meta'):
        if meta.get('http-equiv', '').lower() == 'refresh':
            found_meta = True
            content_val = meta.get('content', '')
            url_m = re.search(r'url=([^\s;]+)', content_val, re.IGNORECASE)
            sec_m = re.search(r'^(\d+)', content_val)
            if url_m:
                redir   = _clean_url(url_m.group(1))
                delay   = sec_m.group(1) if sec_m else '?'
                print(Colors.yellow(f"  [!] Meta refresh → {redir}  (after {delay}s)"))
                short = _is_shortener(redir)
                if short:
                    print(Colors.yellow(f"  [!] URL shortener: {short}"))
                _add(f'meta refresh ({delay}s)', redir)
    if not found_meta:
        print(Colors.green("  [✓] No meta refresh tags found."))

    # ── Anchor links and forms (HTML-level, outside script blocks) ─
    # _collect_all_redirects already handled these when called per script above,
    # but call it once more with EMPTY script text to catch anchors/forms that
    # only appear in HTML with no script context — dedup via seen_keys prevents doubles
    for lbl, url in _collect_all_redirects('', content, soup):
        _add(lbl, url)

    # ── Summary table ─────────────────────────────────────────────
    if collected:
        print(Colors.bold(f"\n╔══════════════════════════════════════════════════════════╗"))
        print(Colors.bold(f"║  URLS / REDIRECTS FOUND — {len(collected)} unique                        ║".replace(
            "                        ║",
            (" " * max(0, 40 - len(str(len(collected))))) + "║"
        )))
        print(Colors.bold(f"╚══════════════════════════════════════════════════════════╝"))
        for lbl, url in collected:
            print(Colors.orange(f"  [{lbl}]"))
            print(Colors.red(  f"    {url}"))

        print(Colors.yellow(f"\n[*] Review each URL interactively:"))
        print("─" * 60)
        for lbl, url in collected:
            _handle_found_url(url, lbl)
    else:
        print(Colors.green("\n[+] No URLs or redirects detected in this file."))

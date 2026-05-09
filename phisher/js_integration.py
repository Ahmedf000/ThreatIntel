import json
import requests
import bs4
import os
from bs4 import BeautifulSoup
import re
from urllib.parse import unquote, urlparse
from colors.color import Colors
from dotenv import load_dotenv
import sys
import platform
import subprocess
from pathlib import Path
import base64
import quopri
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


URL_SHORTENERS_LIST = [
    "bit.ly", "tinyurl.com", "t.ly", "rebrand.ly", "is.gd",
    "goo.su", "qrco.de", "clck.ru", "cutt.ly", "da.gd",
    "rb.gy", "dub.sh", "short.io", "bl.ink", "snipr.sh",
    "ow.ly", "t2mio.com", "tiny.cc", "v.gd", "shorturl.at",
    "spoo.me", "sniply.io", "switchy.io", "golinks.io", "geni.us",
    "kutt.it", "buff.ly", "mzl.la", "bitly.com", "bit.do",
    "lnkiy.com", "shorte.st", "adf.ly", "bc.vc", "tiny.one",
    "u.to", "cutt.us", "git.io", "t.co", "youtu.be",
    "g.co", "fb.me", "t.me", "wp.me", "amzn.to",
    "trib.al", "p3k.io", "soo.gd", "s.id",
    "s.coop", "short.gy", "tinyurl.is", "urlr.me", "tiny.ie",
    "shortcm.li", "tny.im", "vzturl.com", "chilp.it", "y2u.be"
]

SUSPICIOUS_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.scr', '.hta', '.msi', '.iso', '.zip', '.rar', '.7z', '.doc',
    '.docm', '.xlsm', '.pptm', '.pdf', '.lnk', '.wsf', '.sh'
]


def _resolve_eml(file):
    candidate = os.path.expanduser(str(file).strip())
    if candidate.endswith('.eml'):
        candidate = candidate[:-4]

    def try_path(p):
        full = Path(str(p) + '.eml')
        return full if full.exists() else None

    found = try_path(candidate)
    if found:
        return str(found)

    found = try_path(Path.cwd() / Path(candidate).name)
    if found:
        return str(found)

    found = try_path(Path.home() / 'Desktop' / Path(candidate).name)
    if found:
        return str(found)

    raise FileNotFoundError(
        f"[!] Could not find '{Path(candidate).name}.eml' — "
        f"tried: given path, {Path.cwd()}, and {Path.home() / 'Desktop'}."
    )


def _decode_qp(text):
    try:
        return quopri.decodestring(text.encode()).decode('utf-8', errors='replace')
    except Exception:
        return text


def _clean_url(url):
    url = url.strip().rstrip('.,;)\'">')
    url = re.sub(r'=\n', '', url)
    url = url.replace('=3D', '=').replace('=3d', '=')
    url = re.sub(r'\s+', '', url)
    return unquote(url)


def _is_suspicious_url(url):
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if path.endswith(ext):
            return ext
    return None


def _collect_all_redirects(script_text, raw_content, get_html):
    found = []

    JS_PATTERNS = [
        (r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',          'window.location.href'),
        (r'window\.location\.assign\s*\(\s*["\']([^"\']+)["\']',        'window.location.assign()'),
        (r'window\.location\.replace\s*\(\s*["\']([^"\']+)["\']',       'window.location.replace()'),
        (r'window\.location\s*=\s*["\']([^"\']+)["\']',                 'window.location ='),
        (r'document\.location\.href\s*=\s*["\']([^"\']+)["\']',         'document.location.href'),
        (r'document\.location\.assign\s*\(\s*["\']([^"\']+)["\']',      'document.location.assign()'),
        (r'document\.location\.replace\s*\(\s*["\']([^"\']+)["\']',     'document.location.replace()'),
        (r'document\.location\s*=\s*["\']([^"\']+)["\']',               'document.location ='),
        (r'location\.href\s*=\s*["\']([^"\']+)["\']',                   'location.href'),
        (r'location\.assign\s*\(\s*["\']([^"\']+)["\']',                'location.assign()'),
        (r'location\.replace\s*\(\s*["\']([^"\']+)["\']',               'location.replace()'),
        (r'location\s*=\s*["\']([^"\']+)["\']',                         'location ='),
        (r'window\.open\s*\(\s*["\']([^"\']+)["\']',                    'window.open()'),
        (r'self\.location\s*=\s*["\']([^"\']+)["\']',                   'self.location'),
        (r'top\.location\s*=\s*["\']([^"\']+)["\']',                    'top.location'),
        (r'parent\.location\s*=\s*["\']([^"\']+)["\']',                 'parent.location'),
        (r'history\.pushState\s*\([^,]*,[^,]*,\s*["\']([^"\']+)["\']',  'history.pushState()'),
        (r'fetch\s*\(\s*["\']([^"\']+)["\']',                           'fetch()'),
        (r'XMLHttpRequest[^;]*\.open\s*\([^,]+,\s*["\']([^"\']+)["\']', 'XHR.open()'),
        (r'axios\s*\.\s*(?:get|post)\s*\(\s*["\']([^"\']+)["\']',       'axios request'),
        (r'href\s*=\s*["\']?(https?://[^"\'<>\s]+)',                     'raw href attribute'),
    ]

    if script_text:
        for pattern, label in JS_PATTERNS:
            for m in re.finditer(pattern, script_text, re.IGNORECASE | re.DOTALL):
                url = _clean_url(m.group(1))
                if url.startswith('http') or url.startswith('//'):
                    found.append((label, url))

        SETTIMEOUT_PATTERNS = [
            r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{.*?window\.location\.href\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
            r'setTimeout\s*\(\s*\(\s*\)\s*=>\s*\{.*?window\.location\.href\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
            r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{.*?location\.href\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
            r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{.*?window\.location\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
            r'setTimeout\s*\(\s*\(\s*\)\s*=>\s*\{.*?location\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
            r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{.*?document\.location\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
        ]

        for pat in SETTIMEOUT_PATTERNS:
            for m in re.finditer(pat, script_text, re.DOTALL | re.IGNORECASE):
                url = _clean_url(m.group(1))
                delay_s = int(m.group(2)) / 1000
                found.append((f'setTimeout redirect ({delay_s}s)', url))

        SETINTERVAL_PAT = r'setInterval\s*\(\s*function\s*\(\s*\)\s*\{.*?(?:window\.location|location)(?:\.href)?\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)'
        for m in re.finditer(SETINTERVAL_PAT, script_text, re.DOTALL | re.IGNORECASE):
            url = _clean_url(m.group(1))
            found.append(('setInterval redirect', url))

    for tag in get_html.find_all('a', href=True):
        href = _clean_url(tag['href'])
        if href.startswith('http') or href.startswith('//'):
            found.append(('anchor <a href>', href))
            onclick = tag.get('onclick', '')
            if onclick:
                for m in re.finditer(r'(?:location|window\.location)(?:\.href)?\s*=\s*["\']([^"\']+)["\']', onclick):
                    found.append(('onclick redirect', _clean_url(m.group(1))))

    for tag in get_html.find_all('form', action=True):
        action = _clean_url(tag['action'])
        if action.startswith('http') or action.startswith('//'):
            found.append(('form action', action))

    for tag in get_html.find_all('meta'):
        http_equiv = tag.get('http-equiv', '').lower()
        content_val = tag.get('content', '')
        if http_equiv == 'refresh' and content_val:
            url_m = re.search(r'url=([^\s;]+)', content_val, re.IGNORECASE)
            sec_m = re.search(r'^(\d+)', content_val)
            if url_m:
                url = _clean_url(url_m.group(1))
                delay = sec_m.group(1) if sec_m else '?'
                found.append((f'meta http-equiv refresh ({delay}s)', url))

    for tag in get_html.find_all('iframe', src=True):
        src = _clean_url(tag['src'])
        if src.startswith('http') or src.startswith('//'):
            found.append(('iframe src', src))

    for tag in get_html.find_all('img', src=True):
        src = _clean_url(tag['src'])
        if src.startswith('http') and urlparse(src).netloc:
            found.append(('img tracking pixel (possible)', src))

    qp_decoded = _decode_qp(raw_content)
    qp_cleaned = re.sub(r'=\n', '', qp_decoded)
    qp_cleaned = qp_cleaned.replace('=3D', '=').replace('=3d', '=')
    for m in re.finditer(r'href\s*=\s*["\']?(https?://[^\s"\'<>]+)', qp_cleaned, re.IGNORECASE):
        url = _clean_url(m.group(1))
        found.append(('quoted-printable decoded href', url))

    for m in re.finditer(r'<(https?://[^\s>]+)>', raw_content):
        url = _clean_url(m.group(1))
        found.append(('plain text angle-bracket URL', url))

    for m in re.finditer(r'(?<!\w)(https?://[^\s<>"\')\]]+)', raw_content):
        url = _clean_url(m.group(1))
        found.append(('plain text URL', url))

    unique = []
    seen = set()
    for label, url in found:
        if url not in seen and len(url) > 8:
            seen.add(url)
            unique.append((label, url))

    return unique


def _download_payload(url):
    print(Colors.yellow(f"\n[*] Attempting to fetch: {url}"))
    print(Colors.red("[!] WARNING: This fetches content from a potentially malicious URL."))
    confirm = input(Colors.red("    Type 'YES' to confirm download: ")).strip()
    if confirm != 'YES':
        print(Colors.yellow("[*] Download cancelled."))
        return

    save_dir = Path.cwd() / 'payloads'
    save_dir.mkdir(exist_ok=True)

    try:
        parsed = urlparse(url)
        filename = Path(parsed.path).name or 'payload'
        filename = re.sub(r'[\\/*?:"<>|]', '_', filename)
        if not filename or filename == '_':
            filename = 'payload_download'

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        }

        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True, stream=True)

        final_url = resp.url
        if final_url != url:
            print(Colors.orange(f"[!] Followed redirect to: {final_url}"))

        content_type   = resp.headers.get('Content-Type', 'unknown')
        content_length = resp.headers.get('Content-Length', 'unknown')
        print(Colors.cyan(f"[*] Content-Type   : {content_type}"))
        print(Colors.cyan(f"[*] Content-Length : {content_length}"))
        print(Colors.cyan(f"[*] Status Code    : {resp.status_code}"))

        if 'html' in content_type.lower():
            ext = '.html'
        elif 'pdf' in content_type.lower():
            ext = '.pdf'
        elif 'zip' in content_type.lower():
            ext = '.zip'
        elif 'octet-stream' in content_type.lower():
            ext = '.bin'
        else:
            ext = Path(filename).suffix or '.bin'

        if not filename.endswith(ext):
            filename = filename + ext

        save_path = save_dir / filename

        with open(save_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        size = save_path.stat().st_size
        print(Colors.green(f"[+] Saved payload  : {save_path}  ({size} bytes)"))
        print(Colors.red("[!] DO NOT execute this file outside a sandbox environment."))

        ext_flag = _is_suspicious_url(str(save_path))
        if ext_flag:
            print(Colors.red(f"[!] Suspicious file extension detected: {ext_flag}"))

    except requests.exceptions.TooManyRedirects:
        print(Colors.red("[!] Too many redirects — possible redirect loop."))
    except requests.exceptions.SSLError:
        print(Colors.red("[!] SSL error — certificate invalid or self-signed."))
    except requests.exceptions.ConnectionError:
        print(Colors.red("[!] Connection error — host unreachable or refused."))
    except requests.exceptions.Timeout:
        print(Colors.red("[!] Request timed out."))
    except Exception as e:
        print(Colors.red(f"[!] Download failed: {e}"))


def _follow_redirect_chain(url):
    print(Colors.yellow(f"\n[*] Following redirect chain for: {url}"))
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
        session = requests.Session()
        resp = session.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        chain = [r.url for r in resp.history] + [resp.url]
        if len(chain) > 1:
            print(Colors.cyan(f"[*] Redirect chain ({len(chain)} hops):"))
            for i, hop in enumerate(chain):
                print(Colors.cyan(f"    {i+1}. {hop}"))
        else:
            print(Colors.cyan(f"[*] No redirects — final URL: {resp.url}"))
        return resp.url
    except Exception as e:
        print(Colors.red(f"[!] Could not follow redirect: {e}"))
        return url


def expandURL(url):
    load_dotenv()
    TOKEN_EXPANDER = os.getenv("TOKEN_EXPANDER")
    if not TOKEN_EXPANDER:
        print(Colors.yellow("[!] Error grabbing your Token..."))
        print(Colors.yellow("[!] Make sure .env file exists with onesimpleapi TOKEN...Register :)"))
        sys.exit(1)

    URL = "https://onesimpleapi.com/api/unshorten"
    res = requests.post(url=URL,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {TOKEN_EXPANDER}"
                        },
                        json={"output": "json"})
    if res.ok:
        data = res.json()
        return data
    return None


def _handle_found_url(url, label):
    print(Colors.red(f"\n  [{label}]"))
    print(Colors.red(f"  {url}"))

    is_short = next((s for s in URL_SHORTENERS_LIST if s in url), None)
    if is_short:
        print(Colors.yellow(f"  [!] Uses URL shortener ({is_short})"))
        expand_choice = input(Colors.yellow("      Expand short URL? (yes/no): ")).strip().lower()
        if expand_choice == 'yes':
            expanded = expandURL(url)
            if expanded:
                print(Colors.cyan(f"      Expanded: {expanded}"))
                url = expanded if isinstance(expanded, str) else url

    url_decoded = unquote(url)
    if url_decoded != url:
        print(Colors.orange(f"  [!] URL-encoded — decoded: {url_decoded}"))
        url = url_decoded

    ext_flag = _is_suspicious_url(url)
    if ext_flag:
        print(Colors.red(f"  [!] Suspicious extension in URL path: {ext_flag}"))

    action = input(Colors.yellow("  Action: [f]ollow redirects / [d]ownload payload / [s]kip: ")).strip().lower()
    if action == 'f':
        _follow_redirect_chain(url)
    elif action == 'd':
        _download_payload(url)


def javascript_ioc(file):
    eml_path = _resolve_eml(file)

    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    if not content.strip():
        print(Colors.red("[!] File is empty — nothing to analyse."))
        return

    get_html = bs4.BeautifulSoup(content, 'html.parser')
    parse_js = get_html.find_all('script')

    all_redirect_urls = []

    if parse_js:
        for p in parse_js:
            script_text = p.text
            if not script_text.strip():
                continue

            decoded_url  = ''
            decoded_urls = []

            if 'atob(' in script_text:
                print(Colors.orange("[!] Found Base64 decode atob() function"))
                match_base64_decodes = re.findall(r"atob\(['\"]([^'\"]+)['\"]\)", script_text)
                match_base64_decode  = re.findall(r'atob\((.*?)\)', script_text)
                if match_base64_decodes:
                    if len(match_base64_decodes) > 1:
                        print(Colors.yellow("[!] Seems to  be multiple encoded URLs..."))

                    for match in match_base64_decodes:
                        try:
                            print(Colors.green(f"[*] Decoded: {match}. Please Check for Any IoC "))
                            decoded = base64.b64decode(match).decode('utf-8', errors='replace')
                        except Exception as e:
                            decoded = unquote(match)
                        print(Colors.yellow(f"[*] atob() function Decoded: {decoded} -- Check for Any IoC"))
                        decoded_url += decoded
                        decoded_urls.append(decoded)
                else:
                    print(Colors.yellow("[!] atob() call found but couldn't extract argument"))

            if 'eval(' in script_text:
                print(Colors.red("[!] Found execution eval() function"))
                match_eval = re.search(r'eval\((.*?)\)', script_text, re.DOTALL)
                if match_eval:
                    print(f"\t --- {match_eval.group(1)[:120]}")
                    print(Colors.orange("""
                        - Please Trace eval to any URLSearchParams...execution from the param
                        - Check for further IOC for the eval paramter
                        """))

            if 'String.fromCharCode' in script_text:
                print(Colors.orange("[!] Found String.fromCharCode() — possible char-code obfuscation"))
                char_codes = re.findall(r'String\.fromCharCode\(([\d,\s]+)\)', script_text)
                for cc in char_codes:
                    try:
                        chars = ''.join(chr(int(c.strip())) for c in cc.split(',') if c.strip())
                        print(Colors.yellow(f"[*] fromCharCode decoded: {chars}"))
                    except Exception:
                        pass

            if 'unescape(' in script_text or 'decodeURIComponent(' in script_text:
                print(Colors.orange("[!] Found unescape/decodeURIComponent — possible URL obfuscation"))

            redirect_hits = _collect_all_redirects(script_text, content, get_html)
            for label, url in redirect_hits:
                if url not in [u for _, u in all_redirect_urls]:
                    all_redirect_urls.append((label, url))

            settimeout_email = ''
            if 'setTimeout' in script_text:
                print(Colors.orange("[!] Found setTimeout function..Possible for redirection !?"))
                match_redir = re.search(
                    r'setTimeout\s*\(\s*function\s*\(\s*\)\s*\{.*?'
                    r'window\.location\.href\s*=\s*["\']([^"\']+)["\'].*?\}\s*,\s*(\d+)\s*\)',
                    script_text, re.DOTALL
                )
                match_redir1 = re.search(
                    r'setTimeout\s*\(\s*\(\s*\)\s*=>\s*\{.*?\}\s*,\s*(\d+)\s*\)',
                    script_text, re.DOTALL
                )
                match_redir2 = re.search(
                    r'setTimeout\s*\(.*?function\s*\(\s*\)\s*\{.*?window\.location\s*=\s*(https?:[^\s"\']+)',
                    script_text, re.DOTALL
                )

                if match_redir:
                    redir_url    = match_redir.group(1)
                    turn_to_sec  = int(match_redir.group(2)) / 1000
                    print(Colors.red(f"\t[!] Please check  {redir_url} for url redirection..!?\n\t Will redirect after {turn_to_sec} Seconds"))
                    settimeout_email = redir_url
                    if redir_url != unquote(redir_url):
                        print(Colors.orange("[!] It seems the redirection URL is encoded...decoding"))
                        decode_match = unquote(redir_url)
                        if decode_match:
                            print(Colors.yellow(f"[+] The decoded redirection URL is: {decode_match}"))
                    if decoded_url:
                        print(Colors.yellow(f"[*] We comparing the base64 Decode url to the redirection one\n{redir_url}    :   {decoded_url}"))
                    if decoded_urls:
                        print(Colors.yellow("[*] Seems to be more than one direction URL...\n"))
                        for d in decoded_urls:
                            print(Colors.red(f"[*] \t {redir_url}  :  {d}"))

                if match_redir1:
                    turn_to_sec1 = int(match_redir1.group(1)) / 1000
                    print(Colors.red(f"[!] Arrow-function setTimeout fires after {turn_to_sec1}s"))
                if match_redir2:
                    if match_redir2.group(1) != unquote(match_redir2.group(1)):
                        print(Colors.orange(f"[!] setTimeout URL encoded — decoded: {unquote(match_redir2.group(1))}"))
                    else:
                        print(Colors.yellow(f"[*] setTimeout URL: {match_redir2.group(1)}"))

                for u in URL_SHORTENERS_LIST:
                    if settimeout_email and u in settimeout_email:
                        print(Colors.yellow("[*] Seems the redirected URL uses shortening service"))
                        user_option = input("Do you want check for the full URL ? (yes/no)").lower()
                        if user_option == 'yes':
                            print(expandURL(settimeout_email))

                    for d in decoded_urls:
                        if u in d:
                            print(Colors.yellow("[*] Seems the decoded URL from atob() uses shortening service"))
                            user_option = input("Do you want check for the full URL ? (yes/no)").lower()
                            if user_option == 'yes':
                                print(expandURL(d))

    parser_meta = get_html.find_all('meta')
    if parser_meta:
        for meta in parser_meta:
            match_attr = meta.get('content', '')
            if not match_attr:
                continue
            get_url     = re.search(r'url=([^\s;]+)', match_attr, re.IGNORECASE)
            get_seconds = re.search(r'^(\d+)', match_attr)
            if get_url and get_seconds:
                redirect_target = get_url.group(1)
                delay_secs      = get_seconds.group(1)
                print(Colors.yellow(f"[*] Meta-refresh redirect \u2192 {redirect_target}  (after {delay_secs}s)"))
                matched_short = next((s for s in URL_SHORTENERS_LIST if s in redirect_target), None)
                if matched_short:
                    print(Colors.yellow(f"[*] Meta redirect uses URL shortener ({matched_short})"))
                    choice = input("Expand to full URL? (yes/no): ").strip().lower()
                    if choice == 'yes':
                        print(expandURL(redirect_target))
                else:
                    print(Colors.cyan(
                        f"[*] Meta redirect doesn't use a known shortener — still worth investigating: {redirect_target}"))

    extra_redirects = _collect_all_redirects('', content, get_html)
    for label, url in extra_redirects:
        if url not in [u for _, u in all_redirect_urls]:
            all_redirect_urls.append((label, url))

    if all_redirect_urls:
        print(Colors.bold(f"\n[+] === ALL REDIRECTS / URLS FOUND ==="))
        print(Colors.bold(f"    Total: {len(all_redirect_urls)}"))
        print("─" * 60)
        for label, url in all_redirect_urls:
            print(Colors.orange(f"  [{label}]"))
            print(Colors.red(f"    {url}"))
        print("─" * 60)

        print(Colors.yellow("\n[*] Interactive URL analysis — review each one:"))
        for label, url in all_redirect_urls:
            _handle_found_url(url, label)
    else:
        print(Colors.green("[+] No redirect URLs detected in this email."))
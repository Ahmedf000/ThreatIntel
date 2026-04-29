import json
import requests
import bs4
import os
from bs4 import BeautifulSoup
import re
from urllib.parse import unquote
from colors.color import Colors
import os
from dotenv import load_dotenv
import sys

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

def expandURL(url):
    """get the expanded url IF the user adjusted it"""
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
                            "Authorization": "Bearer {TOKEN_EXPANDER}"
                        },
                        json={
                            "output": "json"
                        }
                    )

    if res.ok:
        data = res.json()
        return data
    return None


def javascript_ioc(file):
    """test with the tests html file"""
    with open(f"{file}.eml", 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    get_html = bs4.BeautifulSoup(content, 'html.parser')
    parse_js = get_html.find_all('script')
    if parse_js:
        for p in parse_js:
            script_text = p.text
            decoded_url = ''
            decoded_urls = []

            if 'atob(' in p.text:
                print(Colors.orange(f"[!] Found Base64 decode atob() function"))
                match_base64_decodes = re.findall(r"atob\(['\"]([^'\"]+)['\"]\)", script_text)
                match_base64_decode = re.findall(r'atob\((.*?)\)', p.text)
                if match_base64_decodes:
                    if len(match_base64_decodes) > 1:
                        print(Colors.yellow(f"[!] Seems to  be multiple encoded URLs..."))

                    for match in match_base64_decodes:
                        import base64
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



                if 'eval()' in script_text:
                    print(Colors.red(f"[!] Found execution eval() function"))
                    match_eval = re.match(r'eval\((.*?)\)', script_text, re.DOTALL)
                    if match_eval:
                        print(f"\t --- {match_eval.group(1)[:120]}")
                        print(Colors.orange(f"""
                        - Please Trace eval to any URLSearchParams...execution from the param\n
                        - Check for further IOC for the eval paramter
                        """))


                settimeout_email = ''
                if 'setTimeout' in script_text:

                    """
                    setTimeout(function() {
                    window.location.href = "https://www.example.com";
                    }, 3000); // Redirects after 3 seconds
                    """

                    print(Colors.orange(f"[!] Found setTimeout function..Possible for redirection !?"))
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
                    #setTimeout\(.*?\nwindow\.location.href\s*=\s*(".*?").\n},\s*(\d*)\);
                    if match_redir:
                        redir_url = match_redir.group(1)
                        turn_to_sec = int(match_redir.group(2)) / 1000
                        print(Colors.red(f"\t[!] Please check  {redir_url} for url redirection..!?\n\t Will redirect after {turn_to_sec} Seconds"))
                        settimeout_email = redir_url
                        if redir_url != unquote(redir_url):
                            print(Colors.orange(f"[!] It seems the redirection URL is encoded...decoding"))
                            decode_match = unquote(redir_url)
                            if decode_match:
                                print(Colors.yellow(f"[+] The decoded redirection URL is: {decode_match}"))
                        if decoded_url:
                            print(Colors.yellow(f"[*] We comparing the base64 Decode url to the redirection one\n{redir_url}    :   {decoded_url}"))
                        if decoded_urls:
                            print(Colors.yellow(f"[*] Seems to be more than one direction URL...\n"))
                            for d in decoded_urls:
                                print(Colors.red(f"[*] \t {redir_url}  :  {d}"))

                    if match_redir1:
                        turn_to_sec1 = int(match_redir1.group(1)) / 1000
                        print(Colors.red(f"[!] Arrow-function setTimeout fires after {turn_to_sec1}s"))
                    if match_redir2:
                        if match_redir2.group(1) != unquote(match_redir2.group(1)):
                            print(Colors.orange(f"[!] setTimeout URL encoded — decoded: {unquote(match_redir2.group(1))}"))
                            decode_url_timeout = unquote(match_redir2.group(1))
                        else:
                            print(Colors.yellow(f"[*] setTimeout URL: {match_redir2.group(1)}"))



                for u in URL_SHORTENERS_LIST:
                    if settimeout_email and u in settimeout_email:
                        print(Colors.yellow(f"[*] Seems the redirected URL uses shortening service"))
                        user_option = input(f"Do you want check for the full URL ? (yes/no)").lower()
                        if user_option == 'yes':
                            print(expandURL(settimeout_email))

                    for d in decoded_urls:
                        if u in d:
                            print(Colors.yellow(f"[*] Seems the decoded URL from atob() uses shortening service"))
                            user_option = input(f"Do you want check for the full URL ? (yes/no)").lower()
                            if user_option == 'yes':
                                print(expandURL(d))

        parser_meta = get_html.find_all('meta')
        if parser_meta:
            for meta in parser_meta:
                match_attr = meta.get('content', '')
                if not match_attr:
                    continue

                get_url = re.search(r'url=([^\s;]+)', match_attr, re.IGNORECASE)
                get_seconds = re.search(r'^(\d+)', match_attr)

                if get_url and get_seconds:
                    redirect_target = get_url.group(1)
                    delay_secs = get_seconds.group(1)
                    print(Colors.yellow(f"[*] Meta-refresh redirect → {redirect_target}  (after {delay_secs}s)"))
                    matched_short = next((s for s in URL_SHORTENERS_LIST if s in redirect_target), None)
                    if matched_short:
                        print(Colors.yellow(f"[*] Meta redirect uses URL shortener ({matched_short})"))
                        choice = input("Expand to full URL? (yes/no): ").strip().lower()
                        if choice == 'yes':
                            print(expandURL(redirect_target))
                    else:
                        print(Colors.cyan(
                            f"[*] Meta redirect doesn't use a known shortener — still worth investigating: {redirect_target}"))





"""def test():
    import os
    #MOVE THE REPOSITORY TO UR DESKTOP IF YOU WANT TO RUN A TEST OR CLONE IT THERE
    #ADD BACKSLASH TO THE PATH - OR ADJUST UR PATH TO THE FOLDER PLEASE
    getdir = os.path.join('C:Users\%USERNAME%\Desktop\ThreatIntel', 'Tests', 'test.html')
    if os.path.exists(getdir) and os.path.isfile(getdir):
        javascript_ioc(getdir)
    else:
        print(Colors.yellow(f"[!] test.html not found at {getdir}"))
        print(Colors.yellow("    Make sure Tests/test.html exists in your working directory."))


test()"""






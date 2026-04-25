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



def expandURL(url):
    """get the expanded url IF the user adjusted it"""
    load_dotenv()
    TOKEN_EXPANDER = os.getenv("TOKEN_EXPANDER")
    if not TOKEN_EXPANDER:
        print(Colors.yellow("[!] Error grabbing your Token..."))
        print("[!] Make sure .env file exists with onesimpleapi TOKEN...Register :)")
        sys.exit(1)

    URL = "https://onesimpleapi.com/api/unshorten"
    res = requests.post(url=URL,
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": "Bearer {{TOKEN_EXPANDER}}"
                        },
                        json={
                            "output": "json"
                        }
                    )

    if res.ok:
        data = res.json()
        return data
    return None


def enumerate_login(file):
    """check for the file given with the user desktop
        Is the word "Login" or its corresponding phrase in any language possible on the page?
        Are form tags used on the page?
        Are there expressions such as “Username” or “Password” in the placeholder section of the input fields on the page?
        Are there “Login” or similar expressions in the title or header of the page?
    """
    with open(f'{file}.eml', 'r') as f:
        content = f.read()
        get_html = bs4.BeautifulSoup(content, 'html.parser')
        """working with the script element"""
        parse_js = get_html.find_all('script')
        if parse_js:
            for p in parse_js:
                url_shorteners_list = [
                    "bit.ly", "tinyurl.com", "t.ly", "rebrand.ly", "is.gd",
                    "goo.su", "qrco.de", "clck.ru", "cutt.ly", "da.gd",
                    "rb.gy", "dub.sh", "short.io", "bl.ink", "snipr.sh",
                    "ow.ly", "t2mio.com", "tiny.cc", "v.gd", "shorturl.at",
                    "spoo.me", "sniply.io", "switchy.io", "golinks.io", "geni.us",
                    "kutt.it", "buff.ly", "mzl.la", "bitly.com", "bit.do",
                    "lnkiy.com", "shorte.st", "adf.ly", "bc.vc", "tiny.one",
                    "u.to", "cutt.us", "git.io", "t.co", "youtu.be",
                    "g.co", "fb.me", "t.me", "wp.me", "amzn.to",
                    "trib.al", "bit.ly", "p3k.io", "soo.gd", "s.id",
                    "s.coop", "short.gy", "tinyurl.is", "urlr.me", "tiny.ie",
                    "shortcm.li", "tny.im", "vzturl.com", "chilp.it", "y2u.be"
                ]
                decoded_url = ''
                decoded_urls = []
                if 'atob()' in p.text:
                    print(Colors.red(f"[!] Found Base64 decode atob() function"))
                    match_base64_decode = re.match(r'atob\((.*?)\)', p.text)
                    if match_base64_decode:
                        decoded = unquote(match_base64_decode.group(1))
                        print(Colors.green(f"[*] Decoded: {decoded}. Please Check for Any IoC "))
                        if len(decoded) == 1:
                            decoded_url += decoded
                        if len(decoded) > 1:
                            decoded_urls.append(decoded)


                if 'eval()' in p.text:
                    print(Colors.red(f"[!] Found execution eval() function"))
                    match_eval = re.match(r'eval\((.*?)\)', p.text)
                    if match_eval:
                        print(Colors.red(f"[!] Found eval() Function"))
                        print(Colors.orange(f"""
                        - Please Trace eval to any URLSearchParams...execution from the param\n
                        - Check for further IOC for the eval paramter
                        """))


                settimeout_email = ''
                if 'setTimeout' in p.text:

                    """
                    setTimeout(function() {
                    window.location.href = "https://www.example.com";
                    }, 3000); // Redirects after 3 seconds
                    """

                    print(Colors.orange(f"[!] Found setTimeout function..Possible for redirection !?"))
                    match_redir = re.match(r'setTimeout\(.*?\nwindow\.location.href\s*=\s*(".*?").\n},\s*(\d*)\);', p.text)
                    #setTimeout\(.*?\nwindow\.location.href\s*=\s*(".*?").\n},\s*(\d*)\);
                    if match_redir:
                        turn_to_sec = int(match_redir.group(1)) / 1000
                        print(Colors.red(f"[!] Please check for {match_redir.group(1)} url redirection..!?\n Will redirect after {turn_to_sec} Seconds"))
                        settimeout_email += match_redir.group(1)
                        if decoded_url:
                            print(Colors.yellow(f"[*] We comparing the base64 Decode url to the redirection one\n{match_redir.group(1)}:{decoded_url}"))
                        if decoded_urls:
                            print(Colors.yellow(f"[*] Seems to be more than one direction URL...\n"))
                            for d in decoded_urls:
                                print(Colors.red(f"[*]{match_redir.group(1)}:{d}"))


                for u in url_shorteners_list:
                    if settimeout_email:
                        if str(settimeout_email) in u:
                            print(Colors.yellow(f"[*] Seems the redirected URL uses shortening service"))
                            user_option = input(f"Do you want check for the full URL ? (yes/no)").lower()
                            if user_option == 'yes':
                                check_redirection = expandURL(settimeout_email)
                                print(check_redirection)

                    if decoded_urls:
                        if str(decoded_url) in u:
                            print(Colors.yellow(f"[*] Seems the decoded URL from atob() uses shortening service"))
                            user_option = input(f"Do you want check for the full URL ? (yes/no)").lower()
                            if user_option == 'yes':
                                check_redirection = expandURL(decoded_url)
                                print(check_redirection)

        parser_meta = get_html.find_all('meta')
        if parser_meta:
            for meta in parser_meta:
                get_url = re.match(r'url=(.*?)', meta['content'])
                get_content = re.match(r'\d*', meta['content'])
                if get_url and get_content:
                    print(Colors.yellow(f"[*] Redirection to {get_url.group(1)} after {get_content.group(1)}!"))
                    for s in url_shorteners_list:
                        if get_url.group(1) in s:
                            print(Colors.yellow(f"[*] Seems the redirected meta URL uses shortening service"))
                            user_option = input(f"Do you want check for the full URL ? (yes/no)").lower()
                            if user_option == 'yes':
                                check_redirection = expandURL(s)
                                print(check_redirection)
                        else:
                            print(Colors.yellow(f"[*] The redirection URL doesn't use a shortening service\nworth while checking where it leads"))






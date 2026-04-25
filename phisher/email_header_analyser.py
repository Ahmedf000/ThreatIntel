from email.parser import Parser
from email.policy import default

import os
import subprocess
import platform
import re

import argparse


import sys
import json
from phisher.requestor_VT import request_reputation
from colors.color import Colors





def email_header(file):
    """get the .eml file - better be in Desktop ?"""
    if platform.system() == "Windows":
        cmd = subprocess.run(
            ['powershell', '-NoProfile', '-Command', '(Get-LocalUser | select-object -first 1).tostring()'],
            capture_output=True, text=True).stdout.strip()
        if os.getcwd() != f'C:\\Users\\{cmd}\\Desktop':
            os.chdir(f'C:\\Users\\{cmd}\\Desktop')

    if platform.system() == "Linux":
        cmd = subprocess.run(
            ['whoami'], capture_output=True, text=True
        ).stdout.strip()
        if os.getcwd() != f'/home/{cmd}/Desktop':
            os.chdir(f'/home/{cmd}/Desktop')

    with open(f'{file}.eml', 'r') as f:

        content = f.read()
        headers = Parser(policy=default).parsestr(content)
        deliveredto_ = headers['Delivered-To']
        return_ = headers['Return-Path']
        from_ = headers['From']
        to_ = headers['To']
        reply_to = headers['Reply-To']

        if not return_:
            print(Colors.yellow("[!] Return-Path doesn't exist!"))
        if not reply_to:
            print(Colors.yellow("[!] Reply-To doesn't exist!"))


        headers_list = [
            deliveredto_ or 'N/A',
            return_ or 'N/A',
            from_ or 'N/A',
            to_ or 'N/A',
            reply_to or 'N/A'
        ]

        cleaned_headers_list = []

        for header in headers_list:
            if header == 'N/A':
                cleaned_headers_list.append('N/A')
                continue
            if not '<' in header:
                cleaned_headers_list.append(header)
                continue
            match_re = re.search(r'<(.+?)>', header)
            if match_re:
                cleaned_headers_list.append(match_re.group(1))

        print(cleaned_headers_list)
        name_4_convenience = [
            'Delivered-To',
            'Return-Path',
            'From',
            'To',
            'Reply-To'
        ]

        print(Colors.bold("\n[+] Email Header Analysis"))
        print("─" * 50)
        for raw_email, name_4_con in zip(cleaned_headers_list, name_4_convenience):
            if raw_email:
                print(Colors.blue(f"  {name_4_con:<15}: {raw_email}"))
            else:
                print(Colors.yellow(f"  {name_4_con:<15}: Not present"))

        print("\n")
        print(Colors.yellow("[*] Starting contextual analysis..."))
        print(Colors.yellow("[*] Comparing Reply-to and From emails...."))

        scoring_system = 0
        if len(cleaned_headers_list) > 4 and cleaned_headers_list[4]:

            from_parser = cleaned_headers_list[2].split('@')
            reply_to_parser = cleaned_headers_list[4].split('@')

            if str(from_parser[1]) != str(reply_to_parser[1]):
                scoring_system = 0
                print(Colors.red(f"""
                    ⚠️ UUhh!
                    The From & Reply-to not matching..
                    Please check:
                    {from_parser[1]}
                    {reply_to_parser[1]}
                    with scoring system {scoring_system} As we prefer it NULL.
                """))

            else:
                scoring_system += 20
                print(Colors.green(f"[+] Both From & Reply-to matching. Awesome :)"))
                print(Colors.blue(f"Scoring system up to {scoring_system}."))

        print("\n")
        print(Colors.cyan("Moving to next contextual analysis..."))

        if cleaned_headers_list[1] != 'N/A':

            """Tells SMTP servers where they should send non-delivery notifications. 
            Matching the entire pararagh, isolate it then extract DKIM-DMARC-SPF"""
            getdkim_ = re.compile(r'Authentication-Results:.*?(?=\n\S)', re.DOTALL)
            matchdkim_ = getdkim_.search(content).group()




            if matchdkim_:
                print(Colors.blue("Running the analysis...\n"))
                getdkim_rule_ = re.compile(r'dkim=\S+' ,re.IGNORECASE)
                # \S+ matches everything until the next space/newline
                getdkim_match_ = getdkim_rule_.search(matchdkim_).group()
                if getdkim_match_:
                    check_dkim_pass = getdkim_match_.split('=')
                    print(Colors.yellow("[*] Starting The scoring system..."))
                    moveto_contextual = input \
                        (Colors.yellow("Press enter to start contextual analysis starting with DKIM.."))
                    print(moveto_contextual)
                    if check_dkim_pass[1].lower() == 'pass':
                        scoring_system += 20
                        print(Colors.green(f"[+] DKIM Signature is {check_dkim_pass[1]}"))
                        print(Colors.blue(f"Score is set up to {scoring_system}.\n"))

                    else:
                        scoring_system -= 20
                        print(Colors.red(f""" ===== ⚠️ UUHHH ======
                        The DKIM Signature is {check_dkim_pass[1]} is not valid 
                        Scoring system is now {scoring_system}...
                        """))
                else:
                    scoring_system -= 20
                    print(Colors.red("[!] DKIM Signature not found...."))
                    print(Colors.red(f"Score is down to {scoring_system}."))





                get_return_domain = re.search(r'@\S+', cleaned_headers_list[1]).group()
                get_pure_return_domain = get_return_domain.split('.')
                join_get_pure_return_domain = get_pure_return_domain[1] + '.' + get_pure_return_domain[2]

                get_from_domain = re.search(r'@\S+', cleaned_headers_list[2]).group()
                get_pure_from_domain = get_from_domain.split('.')
                """making sure to strip the @ from the from..."""
                strip_from_at = get_pure_from_domain[0].strip('@')
                join_get_pure_from_domain = strip_from_at + '.' +get_pure_from_domain[1]

                getto_comparison = input(Colors.yellow("Press Enter to move to Return-Path & Path comparison.."))
                print(getto_comparison)
                if join_get_pure_return_domain == join_get_pure_from_domain:
                    scoring_system += 15
                    print(Colors.green(f"""[+] Both From & Return-Path domain matches..."""))
                    print(Colors.blue(f"Great indicator...now scoring system up to {scoring_system}\n"
                                      f""))

                else:
                    print(Colors.red(f"""⚠️ UUUHHH - The From & Return-Path domains are not match please check...
                    {join_get_pure_return_domain}
                    {join_get_pure_from_domain}
                    """))
                    scoring_system = scoring_system - 15

                getdmarc_rule_ = re.compile(r'dmarc=\S+', re.IGNORECASE)
                getdmarc_match_ = getdmarc_rule_.search(matchdkim_).group()
                getto_dmarc = input(Colors.yellow("Press Enter to move to DMARC analysis...."))
                print(getto_dmarc)
                if getdmarc_match_:
                    check_dmarc_pass = getdmarc_match_.split('=')
                    if check_dmarc_pass[1].lower() == 'pass':
                        scoring_system += 10
                        print(Colors.green(f"[+] DMARC Signature is {check_dkim_pass[1]}"))
                        print(Colors.blue(f"[+] Score is set up now to {scoring_system}\n"))
                    else:
                        scoring_system -= 10
                        print(Colors.red(f""" ===== ⚠️ UUHHH ======
                        The DMARC Signature is {check_dkim_pass[1]} is not valid 
                        Scoring system is now {scoring_system}... 
                        """))
                else:
                    scoring_system -= 10
                    print(Colors.red("[!] DMARC Signature not found...."))
                    print(Colors.red(f"Score is down to {scoring_system}."))

                getspf_rule_ = re.compile(r'spf=\S+', re.IGNORECASE)
                getspf_match_ = getspf_rule_.search(matchdkim_).group()
                getto_spf = input(Colors.yellow("Press Enter to move to SPF analysis...."))
                print(getto_spf)
                if getspf_match_:
                    check_spf_pass = getspf_match_.split('=')
                    if check_spf_pass[1].lower() == 'pass':
                        scoring_system += 15
                        print(Colors.green(f"[+] SPF Signature is {check_dkim_pass[1]}"))
                        print(Colors.blue(f"Scoring system is having great score up to {scoring_system}"))
                    else:
                        scoring_system -= 10
                        print(Colors.red(f""" ===== ⚠️ UUHHH ======
                        The SPF Signature is {check_dkim_pass[1]} is not valid 
                        Scoring system is now {scoring_system}... 
                        """))
                else:
                    scoring_system -= 10
                    print(Colors.red("[!] SPF Signature not found...."))
                    print(Colors.red(f"Score is down to {scoring_system}."))

        suggest_further_request = input(Colors.yellow("Do you want to query Virus Total (yes / no):    ")).lower()
        print(suggest_further_request)
        if suggest_further_request == 'yes':
            print(Colors.yellow("[*] Extracting DKIM d= paramter and From Domain before..."))
            getdomains_ = re.compile(r'Authentication-Results:.*?(?=\n\S)', re.DOTALL)
            matchdomain = getdkim_.search(content).group()
            if matchdomain:
                get_thedomain = re.compile(r'@\S+', re.IGNORECASE)
                match_thedomain = get_thedomain.search(matchdkim_).group()
                strip_at_from_domain = match_thedomain.split('@')[1]

                get_thedomain_from = re.compile(r'@\S+', re.IGNORECASE)
                match_thedomain_from = get_thedomain_from.search(cleaned_headers_list[2]).group()
                strip_at_from_domain_2 = match_thedomain_from.split('@')[1]

                if strip_at_from_domain_2 == strip_at_from_domain:
                    print(Colors.yellow(f"""
                    Both From & DKIM Domain matches...
                    {strip_at_from_domain_2}
                    {strip_at_from_domain}
                    """))

                    run_the_request = request_reputation(f"https://{strip_at_from_domain_2}")
                    url_ = run_the_request['url']
                    if run_the_request:

                        url_ = run_the_request['url']

                        if url_.startswith("http://") and not url_.startswith("https://"):
                            print(Colors.orange(
                                f"[!] Warning: {url_} only responds on HTTP — no HTTPS/SSL certificate detected"))
                            print(Colors.orange(f"    Legitimate sites almost always serve HTTPS. Phishing indicator!"))
                            scoring_system -= 10

                        m = run_the_request['malicious']
                        s = run_the_request['suspicious']
                        h = run_the_request['harmless']
                        u = run_the_request['Undetected']

                        if m > 0 and s > 0:
                            print(Colors.red(f"[!] {url_} flagged as MALICIOUS ({m}) and SUSPICIOUS ({s})"))
                            scoring_system -= 50
                        elif m > 0:
                            print(Colors.red(f"[!] {url_} flagged as MALICIOUS — {m} detections"))
                            scoring_system -= 30
                        elif s > 0:
                            print(Colors.orange(f"[!] {url_} flagged as SUSPICIOUS — {s} flags"))
                            scoring_system -= 15
                        else:
                            print(Colors.green(f"[+] {url_} looks clean — Harmless: {h} | Undetected: {u}"))
                            scoring_system += 10

        print(f"Final Score is: {scoring_system}")
        if scoring_system >= 90:
            print(Colors.green(f"[+] Amazing! Final Score: {scoring_system} — Strong legitimacy indicators"))
        elif scoring_system >= 50:
            print(Colors.cyan(f"[+] Good. Final Score: {scoring_system} — Mostly legitimate"))
        elif scoring_system >= 30:
            print(Colors.orange(f"[!] Weak. Final Score: {scoring_system} — Some suspicious indicators"))
        else:
            print(Colors.red(f"[!] Bad. Final Score: {scoring_system} — High phishing likelihood"))


        if suggest_further_request == 'no':
            print(Colors.yellow(f"[*] Finishing up with scoring system! to {scoring_system}"))
            if scoring_system >= 90:
                print(Colors.green(f"[+] Amazing! Final Score: {scoring_system} — Strong legitimacy indicators"))
            elif scoring_system >= 50:
                print(Colors.cyan(f"[+] Good. Final Score: {scoring_system} — Mostly legitimate"))
            elif scoring_system >= 30:
                print(Colors.orange(f"[!] Weak. Final Score: {scoring_system} — Some suspicious indicators"))
            else:
                print(Colors.red(f"[!] Bad. Final Score: {scoring_system} — High phishing likelihood"))




email_header("Important Update to GitHub Copilot Interaction Data Usage Policy")
from email.parser import Parser
from email.policy import default
from collections import Counter
import os
import subprocess
import platform
import re

import requests
import argparse

from dotenv import load_dotenv
import sys
import json

load_dotenv()
API_KEY = os.getenv("VT_API")
if not API_KEY:
    print("[!] Error: API credentials not found!")
    print("[!] Make sure .env file exists with Virus Total API Key...Register :)")
    sys.exit(1)




class Colors:

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    ORANGE = '\033[38;2;255;165;0m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'


    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    END = '\033[0m'

    @staticmethod
    def red(text):
        return f"{Colors.RED}{text}{Colors.END}"

    @staticmethod
    def orange(text):
        return f"{Colors.ORANGE}{text}{Colors.END}"

    @staticmethod
    def green(text):
        return f"{Colors.GREEN}{text}{Colors.END}"

    @staticmethod
    def yellow(text):
        return f"{Colors.YELLOW}{text}{Colors.END}"

    @staticmethod
    def blue(text):
        return f"{Colors.BLUE}{text}{Colors.END}"

    @staticmethod
    def cyan(text):
        return f"{Colors.CYAN}{text}{Colors.END}"

    @staticmethod
    def bold(text):
        return f"{Colors.BOLD}{text}{Colors.END}"

    @staticmethod
    def magenta(text):
        return f"{Colors.MAGENTA}{text}{Colors.END}"





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

    return json.dumps(scanned_url, indent=4) #gave "url": "http://github.com/", not https...





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
                getdkim_rule_ = re.compile(r'dkim=\S+',re.IGNORECASE)
                #\S+ matches everything until the next space/newline
                getdkim_match_ = getdkim_rule_.search(matchdkim_).group()
                if getdkim_match_:
                    check_dkim_pass = getdkim_match_.split('=')
                    print(Colors.yellow("[*] Starting The scoring system..."))
                    moveto_contextual = input(Colors.yellow("Press enter to start contextual analysis starting with DKIM.."))
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



        suggest_further_request = input(Colors.yellow("Do you want to query Virus Total:    ")).lower()
        print(suggest_further_request)
        if suggest_further_request.lower() == 'yes':
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

                    run_the_request = request_reputation(strip_at_from_domain_2)
                    url_ = run_the_request['url']
                    if run_the_request['Undetected'] > 0 and run_the_request['harmless'] > 0 and run_the_request['suspicious'] == 0 and run_the_request['malicious'] == 0:
                        print(Colors.green(f"""[+] {url_} is considered safe with {str({run_the_request['Undetected']})}
                                           {str({run_the_request['harmless']})} rating.
                                           """))
                        scoring_system += 10
                        print(Colors.green(f"Score is up to {scoring_system}."))

                    elif run_the_request['suspicious'] > 0:
                        print(Colors.orange(f"""[+] {url_} have been flagged as suspicious with count
                                        {str(run_the_request['suspicious'])} rating.
                                        """))
                        scoring_system -= 15
                        print(Colors.red(f"Score is down to {scoring_system}."))

                    elif run_the_request['malicious'] > 0:
                        print(Colors.red(f"""[+] {url_} have been flagged as malicious with count
                                         {str(run_the_request['suspicious'])} rating.
                                          """))
                        scoring_system -= 30
                        print(Colors.red(f"Score is down to {scoring_system}."))


                    elif run_the_request['malicious'] > 0 and run_the_request['suspicious'] > 0:
                        print(Colors.red(f"""[+] {url_} have been flagged as suspicious and malicious with count
                                        {str(run_the_request['suspicious'])} and {str(run_the_request['malicious'])} rating.
                                        """))
                        scoring_system -= 50
                        print(Colors.red(f"Score is down to {scoring_system}."))


        print(f"Final Score is: {scoring_system}")
        if scoring_system > 50:
            print(f"Good indicator as Final Score system is above 50")
        if scoring_system < 50:
            print(f"Not great indicator as Final Score system is below 50")
        if scoring_system > 90:
            print(f"Amazing indicator as Final Score system is above 90")
        if scoring_system > 30:
            print(f"Pretty bad indicator as Final Score system is below 30....")

                        




def webserver_logs(file):
    """webserver logs have different format - gonn start with apache based on user picks :)"""
    """Take note that apache has 2 log file - access and error logs"""
    choices_menu = """
    1- Apache Logs
    2- Nginx Logs
    3- IIS Logs
    """ #Menu choice
    webserver_choice = input(Colors.yellow(f"[*] Please choose The webserver you are working with:   ")).lower()
    if webserver_choice == str(1):
        file_apache_choice = input(Colors.yellow(f"[*] Please choose to work with Access(1) or Error Logs(2):   ")).lower()
        if file_apache_choice == str(1):
            print(Colors.yellow(f"[*] Make Sure to move the specific file to work in Desktop"))
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


            with open('access.log', 'r') as f:
                content = f.read()
                pattern_logs = r'^(\S+) - - \[(.*?)\] "(\S+ \S+ \S+)" (\d+) (\d+) "(.*?)" "(.*?)"' #() are capturing groups.
                match_lines_logs = re.match(pattern_logs, content)
                if match_lines_logs:
                    """ 
                    Different ways to analyse the logs...(unordered)
                    - Most repeated IP
                    - Gneral suspicious patterns from GET method group - might write functions for each attack pattern
                            URL DECODE IT :)
                    - response size pattern - will work on specific analysis for it 
                    - user-agent for automated tool ?
                    - time between request - might compare it IF there is scanning tools ?
                    - detect PUT-DELETE requests
                    - Most requested URL information - directory traversal
                    """







    elif webserver_choice == str(2):
        pass

    elif webserver_choice == str(3):
        pass

    else:
        print(Colors.yellow(f"Unrecognized Choice: Check Menu\n {choices_menu}"))





















email_header("Important Update to GitHub Copilot Interaction Data Usage Policy")






def main():
    ASCII = r"""                                                                                                                                                                                                                                       
             _____ _                    _    _____       _       _ 
            /__   \ |__  _ __ ___  __ _| |_  \_   \_ __ | |_ ___| |
              / /\/ '_ \| '__/ _ \/ _` | __|  / /\/ '_ \| __/ _ \ |
             / /  | | | | | |  __/ (_| | |_/\/ /_ | | | | ||  __/ |
             \/   |_| |_|_|  \___|\__,_|\__\____/ |_| |_|\__\___|_|                                                                                                                                                                                                                                              
    """
    #print(Colors.blue(ASCII))


if __name__ == '__main__':
    main()



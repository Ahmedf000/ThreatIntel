from collections import Counter
import os
import subprocess
import platform
import re
from colors.color import Colors
from datetime import date
from datetime import datetime
import requests
import argparse
import sys
import json

from server_logs.SQL_injection_func import SQLi_decode_cond, SQLi_patterns
from server_logs.cmd_injection_func import command_Injection_patterns, decode_encode
from phisher.requestor_VT import request_reputation


def webserver_logs(file):
    print("""
    1- Apache Logs
    2- Nginx Logs
    """)
    webserver_choice = input(Colors.yellow(f"[*] Please choose The webserver you are working with:   ")).lower()

    #
    # APACHE
    #
    if webserver_choice == str(1):
        print(Colors.yellow(f"[*] Make Sure to move the specific file to work in Desktop"))
        if platform.system() == "Windows":
            cmd = subprocess.run(
                ['powershell', '-NoProfile', '-Command', '(Get-LocalUser | select-object -first 1).tostring()'],
                capture_output=True, text=True).stdout.strip()
            if os.getcwd() != f'C:\\Users\\{cmd}\\Desktop':
                os.chdir(f'C:\\Users\\{cmd}\\Desktop')
        if platform.system() == "Linux":
            cmd = subprocess.run(['whoami'], capture_output=True, text=True).stdout.strip()
            if os.getcwd() != f'/home/{cmd}/Desktop':
                os.chdir(f'/home/{cmd}/Desktop')

        with open('access.log', 'r') as f:
            content = f.read()

        pattern_logs = r'^(\S+) - - \[(.*?)\] "(\S+ \S+ \S+)" (\d+) (\d+) "(.*?)" "(.*?)"'
        all_lines = content.splitlines()

        print(Colors.yellow(f"\n{'='*60}"))
        print(Colors.yellow(f"[*] Starting per-line attack pattern analysis..."))
        print(Colors.yellow(f"{'='*60}"))

        for line in all_lines:
            match_lines_logs = re.match(pattern_logs, line)
            if not match_lines_logs:
                continue

            source_ip  = match_lines_logs.group(1)
            request    = match_lines_logs.group(3)
            response   = match_lines_logs.group(4)
            size       = match_lines_logs.group(5)
            user_agent = match_lines_logs.group(7)

            print(Colors.yellow(f"\n[*] --- Analyzing line from IP: {source_ip} ---"))

            # ── SQLi
            print(Colors.yellow(f"\t[*] Checking for SQL Injection patterns...."))
            sqli_pattern = SQLi_decode_cond(request)
            if sqli_pattern:
                print(Colors.red(f"\t[!] SQLi Attack Source IP: {source_ip}"))
                if response == '200' and int(size) == 0:
                    print(Colors.red(f"\t[!] Response 200 OK - 0 bytes. Check IOC"))
                elif response == '200' and 0 < int(size) < 1200:
                    print(Colors.red(f"\t[!] Response 200 OK - {size} bytes (possible DB error - foothold)"))
                elif response == '200' and int(size) > 8000:
                    print(Colors.red(f"\t[!] WARNING: Response {size} bytes - likely successful data exfil"))
                else:
                    print(f"\t[*] Response: {response} | Size: {size}")

            # ── CMDi
            print(Colors.yellow(f"\t[*] Checking for Command Injection patterns...."))
            command_injection_patterns = decode_encode(request)
            if command_injection_patterns:
                print(Colors.red(f"\t[!] CMDi Attack Source IP: {source_ip}"))
                if response == '200' and int(size) == 0:
                    print(Colors.red(f"\t[!] Response 200 OK - 0 bytes. Check IOC"))
                elif response == '200' and 0 < int(size) < 1200:
                    print(Colors.red(f"\t[!] Response 200 OK - {size} bytes (possible error - foothold)"))
                elif response == '200' and int(size) > 8000:
                    print(Colors.red(f"\t[!] WARNING: Response {size} bytes - likely successful OS cmd exec"))
                else:
                    print(f"\t[*] Response: {response} | Size: {size}")

            # ── Automated tools
            if user_agent:
                AUTOMATED_TOOLS = [
                    "Nuclei", "Sqlmap", "Nikto", "Hydra", "Nmap", "fuff",
                    "Masscan", "Metasploit", "Gobuster", "Dirbuster", "OWASP ZAP"
                ]
                for tool in AUTOMATED_TOOLS:
                    if tool in user_agent:
                        print(Colors.magenta(f"\t[!] Automated Tool '{tool}' detected from IP: {source_ip}"))
                        print(Colors.magenta(f"\t\tUser-Agent: {user_agent}"))

        # ── Most repeated IPs
        print(Colors.yellow(f"\n{'='*60}"))
        print(Colors.yellow(f"[*] Checking for The Most repeated IPs...."))
        print(Colors.yellow(f"{'='*60}"))

        ips = []
        for line in all_lines:
            match = re.match(pattern_logs, line)
            if match:
                ips.append(match.group(1))

        get_most = Counter(ips).most_common(5)
        print(Colors.cyan(f"[+] Top 5 IPs by request count:"))
        for ip_entry, cnt in get_most:
            print(Colors.cyan(f"\t{ip_entry}  =>  {cnt} requests"))

        # ── Time analysis
        extracted_all = []
        for g in get_most:
            get_thefull_log = re.findall(rf"^{re.escape(g[0])}.*", content, re.MULTILINE)
            for get_full in get_thefull_log:
                match_full = re.match(pattern_logs, get_full)
                if match_full:
                    extracted_all.append(match_full.group(2))

        print(Colors.yellow(f"\n[*] Running time-frame analysis for top IPs...."))
        if extracted_all:
            _3_first_matches = []
            _3_last_matches  = []
            month_map = {
                'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
            }
            for extracted in extracted_all:
                try_find        = re.compile(r'\d{2}/\w{3}/\d{4}')
                try_find_second = re.compile(r'(\d{2}:\d{2}:\d{2})')
                for gft in try_find.findall(extracted):
                    _3_first_matches.append(gft)
                for gfs in try_find_second.findall(extracted):
                    _3_last_matches.append(gfs)

            count = 0
            final_time_list = []
            for _3 in _3_first_matches:
                parts = _3_first_matches[count].split('/')
                day   = parts[0]
                month = parts[1]
                year  = parts[2]
                formated_proper_date = year + '-' + month_map[month] + '-' + day
                final_time_list.append(formated_proper_date)
                count += 1

            _get_mid_date_ = []
            print(Colors.yellow(f"[*] Working on {date.today().year} only..."))
            for final in final_time_list:
                if int(final.split('-')[0]) == date.today().year:
                    _get_mid_date_.append(final)

            full_date = []
            for first, second in zip(_get_mid_date_, _3_last_matches):
                full_date.append(first + ':' + second)


            month_extractor = []
            for full in full_date:
                match_it = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                if match_it:
                    month_extractor.append(match_it.group(1) + ':' + match_it.group(2) + ':' + match_it.group(3))

            month_mapper = {
                '01': 'January', '02': 'February', '03': 'March', '04': 'April',
                '05': 'May', '06': 'June', '07': 'July', '08': 'August',
                '09': 'September', '10': 'October', '11': 'November', '12': 'December'
            }

            if not month_extractor:
                print(Colors.yellow("[!] No dates matched current year - skipping busy-day analysis."))
            else:
                month_only_list = [e.split(':')[1] for e in month_extractor]
                get_most_month  = Counter(month_only_list).most_common(1)[0][0]
                wrapper         = month_mapper.get(get_most_month, get_most_month)
                print(Colors.green(f"[+] {wrapper} Appears to be the busiest month...."))

                busy_day = []
                for entry in month_extractor:
                    parts = entry.split(':')
                    if parts[1] == get_most_month:
                        busy_day.append(parts[2])

                match_most_busy_day = Counter(busy_day).most_common(5)
                while len(match_most_busy_day) < 5:
                    match_most_busy_day.append(('N/A', 0))

                print(Colors.green(
                    f"\n\t[+] Within Month: {wrapper}\n"
                    f"\tMost Busy Days in the Logs:\n"
                    f"\t\t{match_most_busy_day[0]} #1\n"
                    f"\t\t{match_most_busy_day[1]} #2\n"
                    f"\t\t{match_most_busy_day[2]} #3\n"
                    f"\t\t{match_most_busy_day[3]} #4\n"
                    f"\t\t{match_most_busy_day[4]} #5\n"
                ))

                count = 0
                for g in get_most:
                    ip_add = g[0]
                    for get_line in all_lines:
                        m1 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[0][0]))})', get_line)
                        m2 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[1][0]))})', get_line)
                        m3 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[2][0]))})', get_line)
                        m4 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[3][0]))})', get_line)
                        m5 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[4][0]))})', get_line)
                        if m1: print(Colors.cyan(f"\t[+] {g} - active on 1st most busy day of {wrapper}"))
                        if m2: print(Colors.cyan(f"\t[+] {g} - active on 2nd most busy day of {wrapper}"))
                        if m3: print(Colors.cyan(f"\t[+] {g} - active on 3rd most busy day of {wrapper}"))
                        if m4: print(Colors.cyan(f"\t[+] {g} - active on 4th most busy day of {wrapper}"))
                        if m5: print(Colors.cyan(f"\t[+] {g} - active on 5th most busy day of {wrapper}"))
                    count += 1

        # ── VT lookup
        ask_checking_ip_from_attacks = input(Colors.green(
            f'\n[*] Do you want to check any of the IPs in the attack pattern logs: (yes/no)   '
        )).lower()
        print(ask_checking_ip_from_attacks)

        if ask_checking_ip_from_attacks == 'yes':
            print(Colors.yellow(f"[*] Running VirusTotal lookup on top IPs..."))
            for ip_entry, cnt in get_most:
                print(Colors.cyan(f"\n\t[*] Querying: {ip_entry}  (seen {cnt} times)"))
                result = request_reputation(f"https://{ip_entry}")
                if result:
                    if result['malicious'] > 0:
                        print(Colors.red(f"\t[!] MALICIOUS - {result['malicious']} detections  |  {ip_entry}"))
                    elif result['suspicious'] > 0:
                        print(Colors.orange(f"\t[!] SUSPICIOUS - {result['suspicious']} flags  |  {ip_entry}"))
                    else:
                        print(Colors.green(f"\t[+] Clean - Harmless: {result['harmless']} | Undetected: {result['Undetected']}  |  {ip_entry}"))
                else:
                    print(Colors.yellow(f"\t[!] No result returned for {ip_entry}"))
                print()

        if ask_checking_ip_from_attacks == 'no':
            print(Colors.yellow("[*] Skipping IP reputation check."))

    #
    # NGINX
    #
    elif webserver_choice == str(2):
        file_apache_choice = input(
            Colors.yellow(f"[*] Please choose to work with Access(1) or Error Logs(2):   ")).lower()
        if file_apache_choice == str(1):
            print(Colors.yellow(f"[*] Make Sure to move the specific file to work in Desktop"))
            if platform.system() == "Windows":
                cmd = subprocess.run(
                    ['powershell', '-NoProfile', '-Command', '(Get-LocalUser | select-object -first 1).tostring()'],
                    capture_output=True, text=True).stdout.strip()
                if os.getcwd() != f'C:\\Users\\{cmd}\\Desktop':
                    os.chdir(f'C:\\Users\\{cmd}\\Desktop')
            if platform.system() == "Linux":
                cmd = subprocess.run(['whoami'], capture_output=True, text=True).stdout.strip()
                if os.getcwd() != f'/home/{cmd}/Desktop':
                    os.chdir(f'/home/{cmd}/Desktop')

            with open('access.log', 'r') as f:
                content = f.read()

            pattern_logs = r'^(\S+) - - \[(.*?)\] "(\S+ \S+ \S+)" (\d+) (\d+) "(.*?)" "(.*?)"'
            all_lines = content.splitlines()

            print(Colors.yellow(f"\n{'='*60}"))
            print(Colors.yellow(f"[*] Starting per-line attack pattern analysis..."))
            print(Colors.yellow(f"{'='*60}"))

            for line in all_lines:
                match_lines_logs = re.match(pattern_logs, line)
                if not match_lines_logs:
                    continue

                source_ip  = match_lines_logs.group(1)
                request    = match_lines_logs.group(3)
                response   = match_lines_logs.group(4)
                size       = match_lines_logs.group(5)
                user_agent = match_lines_logs.group(7)

                print(Colors.yellow(f"\n[*] --- Analyzing line from IP: {source_ip} ---"))

                print(Colors.yellow(f"\t[*] Checking for SQL Injection patterns...."))
                sqli_patterns = SQLi_decode_cond(request)
                if sqli_patterns:
                    print(Colors.red(f"\t[!] SQLi Attack Source IP: {source_ip}"))
                    if response == '200' and int(size) == 0:
                        print(Colors.red(f"\t[!] Response 200 OK - 0 bytes. Check IOC"))
                    elif response == '200' and 0 < int(size) < 1200:
                        print(Colors.red(f"\t[!] Response 200 OK - {size} bytes (possible DB error - foothold)"))
                    elif response == '200' and int(size) > 8000:
                        print(Colors.red(f"\t[!] WARNING: Response {size} bytes - likely successful data exfil"))
                    else:
                        print(f"\t[*] Response: {response} | Size: {size}")

                print(Colors.yellow(f"\t[*] Checking for Command Injection patterns...."))
                command_injection_patterns = decode_encode(request)
                if command_injection_patterns:
                    print(Colors.red(f"\t[!] CMDi Attack Source IP: {source_ip}"))
                    if response == '200' and int(size) == 0:
                        print(Colors.red(f"\t[!] Response 200 OK - 0 bytes. Check IOC"))
                    elif response == '200' and 0 < int(size) < 1200:
                        print(Colors.red(f"\t[!] Response 200 OK - {size} bytes (possible error - foothold)"))
                    elif response == '200' and int(size) > 8000:
                        print(Colors.red(f"\t[!] WARNING: Response {size} bytes - likely successful OS cmd exec"))
                    else:
                        print(f"\t[*] Response: {response} | Size: {size}")

                if user_agent:
                    AUTOMATED_TOOLS = [
                        "Nuclei", "Sqlmap", "Nikto", "Hydra", "Nmap", "fuff",
                        "Masscan", "Metasploit", "Gobuster", "Dirbuster", "OWASP ZAP"
                    ]
                    for tool in AUTOMATED_TOOLS:
                        if tool in user_agent:
                            print(Colors.magenta(f"\t[!] Automated Tool '{tool}' detected from IP: {source_ip}"))
                            print(Colors.magenta(f"\t\tUser-Agent: {user_agent}"))

            print(Colors.yellow(f"\n{'='*60}"))
            print(Colors.yellow(f"[*] Checking for The Most repeated IPs...."))
            print(Colors.yellow(f"{'='*60}"))

            ips = []
            for line in all_lines:
                match = re.match(pattern_logs, line)
                if match:
                    ips.append(match.group(1))

            get_most = Counter(ips).most_common(5)
            print(Colors.cyan(f"[+] Top 5 IPs by request count:"))
            for ip_entry, cnt in get_most:
                print(Colors.cyan(f"\t{ip_entry}  =>  {cnt} requests"))

            extracted_all = []
            for g in get_most:
                get_thefull_log = re.findall(rf"^{re.escape(g[0])}.*", content, re.MULTILINE)
                for get_full in get_thefull_log:
                    match_full = re.match(pattern_logs, get_full)
                    if match_full:
                        extracted_all.append(match_full.group(2))

            print(Colors.yellow(f"\n[*] Running time-frame analysis for top IPs...."))
            if extracted_all:
                _3_first_matches = []
                _3_last_matches  = []
                month_map = {
                    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
                }
                for extracted in extracted_all:
                    try_find        = re.compile(r'\d{2}/\w{3}/\d{4}')
                    try_find_second = re.compile(r'(\d{2}:\d{2}:\d{2})')
                    for gft in try_find.findall(extracted):
                        _3_first_matches.append(gft)
                    for gfs in try_find_second.findall(extracted):
                        _3_last_matches.append(gfs)

                count = 0
                final_time_list = []
                for _3 in _3_first_matches:
                    parts = _3_first_matches[count].split('/')
                    day   = parts[0]
                    month = parts[1]
                    year  = parts[2]
                    formated_proper_date = year + '-' + month_map[month] + '-' + day
                    final_time_list.append(formated_proper_date)
                    count += 1

                _get_mid_date_ = []
                print(Colors.yellow(f"[*] Working on {date.today().year} only..."))
                for final in final_time_list:
                    if int(final.split('-')[0]) == date.today().year:
                        _get_mid_date_.append(final)

                full_date = []
                for first, second in zip(_get_mid_date_, _3_last_matches):
                    full_date.append(first + ':' + second)

                month_extractor = []
                for full in full_date:
                    match_it = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                    if match_it:
                        month_extractor.append(match_it.group(1) + ':' + match_it.group(2) + ':' + match_it.group(3))

                month_mapper = {
                    '01': 'January', '02': 'February', '03': 'March', '04': 'April',
                    '05': 'May', '06': 'June', '07': 'July', '08': 'August',
                    '09': 'September', '10': 'October', '11': 'November', '12': 'December'
                }

                if not month_extractor:
                    print(Colors.yellow("[!] No dates matched current year - skipping busy-day analysis."))
                else:
                    month_only_list = [e.split(':')[1] for e in month_extractor]
                    get_most_month  = Counter(month_only_list).most_common(1)[0][0]
                    change_month    = month_mapper.get(get_most_month, get_most_month)
                    print(Colors.green(f"[+] {change_month} Appears to be the busiest month...."))

                    busy_day = []
                    for entry in month_extractor:
                        parts = entry.split(':')
                        if parts[1] == get_most_month:
                            busy_day.append(parts[2])

                    match_most_busy_day = Counter(busy_day).most_common(5)
                    while len(match_most_busy_day) < 5:
                        match_most_busy_day.append(('N/A', 0))

                    print(Colors.green(
                        f"\n\t[+] Within Month: {change_month}\n"
                        f"\tMost Busy Days in the Logs:\n"
                        f"\t\t{match_most_busy_day[0]} #1\n"
                        f"\t\t{match_most_busy_day[1]} #2\n"
                        f"\t\t{match_most_busy_day[2]} #3\n"
                        f"\t\t{match_most_busy_day[3]} #4\n"
                        f"\t\t{match_most_busy_day[4]} #5\n"
                    ))

                    count = 0
                    for g in get_most:
                        ip_add = g[0]
                        for get_line in all_lines:
                            m1 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[0][0]))})', get_line)
                            m2 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[1][0]))})', get_line)
                            m3 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[2][0]))})', get_line)
                            m4 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[3][0]))})', get_line)
                            m5 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[4][0]))})', get_line)
                            if m1: print(Colors.cyan(f"\t[+] {g} - active on 1st most busy day of {change_month}"))
                            if m2: print(Colors.cyan(f"\t[+] {g} - active on 2nd most busy day of {change_month}"))
                            if m3: print(Colors.cyan(f"\t[+] {g} - active on 3rd most busy day of {change_month}"))
                            if m4: print(Colors.cyan(f"\t[+] {g} - active on 4th most busy day of {change_month}"))
                            if m5: print(Colors.cyan(f"\t[+] {g} - active on 5th most busy day of {change_month}"))
                        count += 1

            ask_checking_ip_from_attacks = input(Colors.green(
                f'\n[*] Do you want to check any of the IPs in the attack pattern logs: (yes/no)   '
            )).lower()
            print(ask_checking_ip_from_attacks)

            if ask_checking_ip_from_attacks == 'yes':
                print(Colors.yellow(f"[*] Running VirusTotal lookup on top IPs..."))
                for ip_entry, cnt in get_most:
                    print(Colors.cyan(f"\n\t[*] Querying: {ip_entry}  (seen {cnt} times)"))
                    result = request_reputation(f"https://{ip_entry}")
                    if result:
                        if result['malicious'] > 0:
                            print(Colors.red(f"\t[!] MALICIOUS - {result['malicious']} detections  |  {ip_entry}"))
                        elif result['suspicious'] > 0:
                            print(Colors.orange(f"\t[!] SUSPICIOUS - {result['suspicious']} flags  |  {ip_entry}"))
                        else:
                            print(Colors.green(f"\t[+] Clean - Harmless: {result['harmless']} | Undetected: {result['Undetected']}  |  {ip_entry}"))
                    else:
                        print(Colors.yellow(f"\t[!] No result returned for {ip_entry}"))
                    print()

            if ask_checking_ip_from_attacks == 'no':
                print(Colors.yellow("[*] Skipping IP reputation check."))

    else:
        print(Colors.yellow(f"Unrecognized Choice: Check Menu\n {webserver_choice}"))
        sys.exit(1)




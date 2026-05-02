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
    """webserver logs have different format - gonn start with apache based on user picks :)"""
    """Take note that apache has 2 log file - access and error logs"""
    print("""
    1- Apache Logs
    2- Nginx Logs
    """)
    webserver_choice = input(Colors.yellow(f"[*] Please choose The webserver you are working with:   ")).lower()
    if webserver_choice == str(1):
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

        pattern_logs = r'^(\S+) - - \[(.*?)\] "(\S+ \S+ \S+)" (\d+) (\d+) "(.*?)" "(.*?)"'

        for line in content.splitlines():
            match_lines_logs = re.match(pattern_logs, line)
            if not match_lines_logs:
                continue

            if match_lines_logs.group(3):
                print(Colors.yellow(f"[*] Analyzing HTTP REQUEST Attack Patterns if any...."))
                print(Colors.yellow(f"[*] Checking for SQL Injection patterns...."))
                sqli_patterns = SQLi_decode_cond(match_lines_logs.group(3))
                if sqli_patterns:
                    response = match_lines_logs.group(4)
                    size = match_lines_logs.group(5)
                    if response == '200' and int(size) == 0:
                        print(Colors.red(f"[!] The response for the attack is 200 - OK with 0 bytes response..."))
                        print(Colors.red(f"[!] Please further check for the IOC "))
                    elif response == '200' and 0 < int(size) < 1200:
                        print(Colors.red(f"""[!] The response for the attack is 200 - OK 
                             The response size with {int(size)} bytes.... 
                             the size may indicates error response from DB - A foothold for the threat actor   """))
                        print(Colors.red(f"[!] Please further check for the IOC "))
                    elif response == '200' and int(size) > 8000:
                        print(Colors.red(f"""[!] WARNING: Reponse is {int(size)} bytes....a successful attack
                        Likely Threat actor retrieved information from the DB"""))
                        print(Colors.red(f"[!] Please further check for the IOC "))
                    else:
                        print("Error reading the response and status code")

                move_to_next = input("Press Enter to move to next pattern ")
                print(move_to_next)

                print(Colors.yellow(f"[*] Checking for Command injection patterns...."))
                command_injection_patterns = decode_encode(match_lines_logs.group(3))
                if command_injection_patterns:
                    response_ = match_lines_logs.group(4)
                    size_ = match_lines_logs.group(5)
                    if response_ == '200' and int(size_) == 0:
                        print(Colors.red(f"[!] The response for the attack is 200 - OK with 0 bytes response..."))
                        print(Colors.red(f"[!] Please further check for the IOC "))
                    elif response_ == '200' and 0 < int(size_) < 1200:
                        print(Colors.red(f"""[!] The response for the attack is 200 - OK 
                                                     The response size with {int(size_)} bytes.... 
                                                     the size may indicates error response - A foothold for the threat actor   """))
                        print(Colors.red(f"[!] Please further check for the IOC "))
                    elif response_ == '200' and int(size_) > 8000:
                        print(Colors.red(f"""[!] WARNING: Reponse is {int(size_)} bytes....a successful attack
                        Likely Threat actor executed OS shell commands"""))
                        print(Colors.red(f"[!] Please further check for the IOC "))
                    else:
                        print("Error reading the response and status code")

                move_to_next = input("Press Enter to move to next pattern ")
                print(move_to_next)

                if match_lines_logs.group(7):
                    AUTOMATED_TOOLS = [
                        "Nuclei", "Sqlmap", "Nikto", "Hydra", "Nmap", "fuff", "Masscan", "Metasploit",
                        "Gobuster", "Dirbuster", "OWASP ZAP"
                    ]
                    detect_rule = {}
                    for tool in AUTOMATED_TOOLS:
                        if tool in match_lines_logs.group(7):
                            detect_rule[f"{tool} Found in Logs"] = match_lines_logs.group(7)
                    if detect_rule:
                        print(detect_rule)

        """get MOST repeated IP"""
        ips = []
        print(Colors.yellow(f"[*] Checking for The Most repeated IP...."))
        for line in content.splitlines():
            match = re.match(pattern_logs, line)
            if match:
                ips.append(match.group(1))

        get_most = Counter(ips).most_common(5)

        extracted_all = []
        for g in get_most:
            get_thefull_log = re.findall(rf"^{re.escape(g[0])}.*", content, re.MULTILINE)

            for get_full in get_thefull_log:
                match_full = re.match(pattern_logs, get_full)
                if match_full:
                    get_time_fromip = match_full.group(2)
                    strip_off_time = re.findall(r"\d\d/\w\w\w/\d\d\d\d:\d\d:\d\d:\d\d", get_time_fromip)
                    extracted_all.append(get_time_fromip)

        print(Colors.yellow(f"[*] Checking for suspicious short period requests that belong to {get_most} IP...."))
        if extracted_all:
            count = 0
            _3_first_matches = []
            _3_last_matches = []
            month_map = {
                'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
            }
            for extracted in extracted_all:
                try_find = re.compile(r'\d{2}/\w{3}/\d{4}')
                try_find_second = re.compile(r'(\d{2}:\d{2}:\d{2})')
                good_format_time = try_find.findall(extracted)
                good_format_second = try_find_second.findall(extracted)
                for gft in good_format_time:
                    _3_first_matches.append(gft)
                for gfs in good_format_second:
                    _3_last_matches.append(gfs)

            count = 0
            final_time_list = []
            if _3_first_matches:
                for _3 in _3_first_matches:
                    split_3_parts = _3_first_matches[count].split('/')
                    day = split_3_parts[0]
                    month = split_3_parts[1]
                    year = split_3_parts[2]
                    month_update = month_map[month]
                    formated_proper_date = year + '-' + month_update + '-' + day
                    final_time_list.append(formated_proper_date)
                    count = count + 1

            _get_mid_date_ = []
            if final_time_list:
                print(Colors.yellow(f"[*] Working on {date.today().year} only..."))
                for final in final_time_list:
                    get_year = int(final.split('-')[0])
                    if get_year == date.today().year:
                        _get_mid_date_.append(final)

            full_date = []
            for first, second in zip(_get_mid_date_, _3_last_matches):
                full_date.append(first + ':' + second)

            month_extractor = []
            day_extractor = []
            for full in full_date:
                match_it = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                match_it_2 = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                if match_it:
                    month_extractor.append(match_it.groups(1))
                if match_it_2:
                    day_extractor.append(match_it_2.groups(1) + ':' + match_it_2.groups(2))

            month_mapper = {
                '01': 'January', '02': 'February', '03': 'March', '04': 'April',
                '05': 'May', '06': 'June', '07': 'July', '08': 'August',
                '09': 'September', '10': 'October', '11': 'November', '12': 'December'
            }

            work_up_day = []
            get_most_month = Counter(month_extractor).most_common(1)[0][0]
            change_month = month_mapper.get(get_most_month[1], get_most_month[1])
            print(Colors.green(f"[+] {change_month} Appears to be the most busy month...."))
            for d in day_extractor:
                if get_most_month[1] in d:
                    work_up_day.append(d)

            busy_day = []
            if work_up_day:
                for w in work_up_day:
                    match_repeated_day = re.match(r'\d\d', w)
                    if match_repeated_day:
                        busy_day.append(w)
            match_most_busy_day = Counter(busy_day).most_common(5)

            while len(match_most_busy_day) < 5:
                match_most_busy_day.append(('N/A', 0))

            print(Colors.green(f"""
                [+] Within Month: {change_month}
                The Three Most Busy Days appears to be in the Logs:
                        {match_most_busy_day[0]} #1
                        {match_most_busy_day[1]} #2
                        {match_most_busy_day[2]} #3
                        {match_most_busy_day[3]} #4
                        {match_most_busy_day[4]} #5
            """))

            get_back_content = []
            for c in content.splitlines():
                get_back_content.append(c)
            count = 0
            for g in get_most:
                ip_add = g[0]
                for get in get_back_content:
                    match_all_specifically_day1 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[0][0]))})', get)
                    match_all_specifically_day2 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[1][0]))})', get)
                    match_all_specifically_day3 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[2][0]))})', get)
                    match_all_specifically_day4 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[3][0]))})', get)
                    match_all_specifically_day5 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[4][0]))})', get)
                    if match_all_specifically_day1:
                        print(Colors.cyan(f"""[+] {g} Appears to be in the 1st most busy day from 
                                                        {change_month} - Which Busy Month from the Logs...."""))
                    if match_all_specifically_day2:
                        print(Colors.cyan(f"""[+] {g} Appears to be in the 2nd most busy day from 
                                                        {change_month} - Which Busy Month from the Logs...."""))
                    if match_all_specifically_day3:
                        print(Colors.cyan(f"""[+] {g} Appears to be in the 3rd most busy day from 
                                                        {change_month} - Which Busy Month from the Logs...."""))
                    if match_all_specifically_day4:
                        print(Colors.cyan(f"""[+] {g} Appears to be in the 4th most busy day from 
                                                        {change_month} - Which Busy Month from the Logs...."""))
                    if match_all_specifically_day5:
                        print(Colors.cyan(f"""[+] {g} Appears to be in the 5th most busy day from 
                                                        {change_month} - Which Busy Month from the Logs...."""))

                count += 1

        ask_checking_ip_from_attacks = input(Colors.green(f"""[*] Do you want to check any of the IPS in the attack"
                                                          pattern logs:         (yes/no)""")).lower()
        print(ask_checking_ip_from_attacks)

        if ask_checking_ip_from_attacks == 'yes':
            print(Colors.yellow(f"[*] Running VirusTotal lookup on top IPs..."))
            for ip, count in get_most:
                print(Colors.cyan(f"\n[*] Querying: {ip}"))
                result = request_reputation(f"https://{ip}")
                if result:
                    if result['malicious'] > 0:
                        print(Colors.red(f"  [!] MALICIOUS — {result['malicious']} detections"))
                    elif result['suspicious'] > 0:
                        print(Colors.orange(f"  [!] SUSPICIOUS — {result['suspicious']} flags"))
                    else:
                        print(Colors.green(
                            f"  [+] Clean — Harmless: {result['harmless']} | Undetected: {result['Undetected']}"))

        if ask_checking_ip_from_attacks == 'no':
            print(Colors.yellow("[*] Skipping IP reputation check."))

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
                cmd = subprocess.run(
                    ['whoami'], capture_output=True, text=True
                ).stdout.strip()
                if os.getcwd() != f'/home/{cmd}/Desktop':
                    os.chdir(f'/home/{cmd}/Desktop')

            with open('access.log', 'r') as f:
                content = f.read()

            pattern_logs = r'^(\S+) - - \[(.*?)\] "(\S+ \S+ \S+)" (\d+) (\d+) "(.*?)" "(.*?)"'

            for line in content.splitlines():
                match_lines_logs = re.match(pattern_logs, line)
                if not match_lines_logs:
                    continue

                if match_lines_logs.group(3):
                    print(Colors.yellow(f"[*] Analyzing HTTP REQUEST Attack Patterns if any...."))
                    print(Colors.yellow(f"[*] Checking for SQL Injection patterns...."))
                    sqli_patterns = SQLi_decode_cond(match_lines_logs.group(3))
                    if sqli_patterns:
                        response = match_lines_logs.group(4)
                        size = match_lines_logs.group(5)
                        if response == '200' and int(size) == 0:
                            print(Colors.red(f"[!] The response for the attack is 200 - OK with 0 bytes response..."))
                            print(Colors.red(f"[!] Please further check for the IOC "))
                        elif response == '200' and 0 < int(size) < 1200:
                            print(Colors.red(f"""[!] The response for the attack is 200 - OK 
                                             The response size with {int(size)} bytes.... 
                                             the size may indicates error response from DB - A foothold for the threat actor   """))
                            print(Colors.red(f"[!] Please further check for the IOC "))
                        elif response == '200' and int(size) > 8000:
                            print(Colors.red(f"""[!] WARNING: Reponse is {int(size)} bytes....a successful attack
                                        Likely Threat actor retrieved information from the DB"""))
                            print(Colors.red(f"[!] Please further check for the IOC "))
                        else:
                            print("Error reading the response and status code")

                    move_to_next = input("Press Enter to move to next pattern ")
                    print(move_to_next)

                    print(Colors.yellow(f"[*] Checking for Command injection patterns...."))
                    command_injection_patterns = decode_encode(match_lines_logs.group(3))
                    if command_injection_patterns:
                        response_ = match_lines_logs.group(4)
                        size_ = match_lines_logs.group(5)
                        if response_ == '200' and int(size_) == 0:
                            print(Colors.red(f"[!] The response for the attack is 200 - OK with 0 bytes response..."))
                            print(Colors.red(f"[!] Please further check for the IOC "))
                        elif response_ == '200' and 0 < int(size_) < 1200:
                            print(Colors.red(f"""[!] The response for the attack is 200 - OK 
                                                                         The response size with {int(size_)} bytes.... 
                                                                         the size may indicates error response - A foothold for the threat actor   """))
                            print(Colors.red(f"[!] Please further check for the IOC "))
                        elif response_ == '200' and int(size_) > 8000:
                            print(Colors.red(f"""[!] WARNING: Reponse is {int(size_)} bytes....a successful attack
                                    Likely Threat actor executed OS shell commands"""))
                            print(Colors.red(f"[!] Please further check for the IOC "))
                        else:
                            print("Error reading the response and status code")

                    move_to_next = input("Press Enter to move to next pattern ")
                    print(move_to_next)

                    if match_lines_logs.group(7):
                        AUTOMATED_TOOLS = [
                            "Nuclei", "Sqlmap", "Nikto", "Hydra", "Nmap", "fuff", "Masscan", "Metasploit",
                            "Gobuster", "Dirbuster", "OWASP ZAP"
                        ]
                        detect_rule = {}
                        for tool in AUTOMATED_TOOLS:
                            if tool in match_lines_logs.group(7):
                                detect_rule[f"{tool} Found in Logs"] = match_lines_logs.group(7)
                        if detect_rule:
                            print(detect_rule)

            ips = []
            print(Colors.yellow(f"[*] Checking for The Most repeated IP...."))
            for line in content.splitlines():
                match = re.match(pattern_logs, line)
                if match:
                    ips.append(match.group(1))

            get_most = Counter(ips).most_common(5)

            extracted_all = []
            for g in get_most:
                get_thefull_log = re.findall(rf"^{re.escape(g[0])}.*", content, re.MULTILINE)

                for get_full in get_thefull_log:
                    match_full = re.match(pattern_logs, get_full)
                    if match_full:
                        get_time_fromip = match_full.group(2)
                        strip_off_time = re.findall(r"\d\d/\w\w\w/\d\d\d\d:\d\d:\d\d:\d\d", get_time_fromip)
                        extracted_all.append(get_time_fromip)

            print(Colors.yellow(f"[*] Checking for suspicious short period requests that belong to {get_most} IP...."))
            if extracted_all:
                count = 0
                _3_first_matches = []
                _3_last_matches = []
                month_map = {
                    'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                    'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                    'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
                }
                for extracted in extracted_all:
                    try_find = re.compile(r'\d{2}/\w{3}/\d{4}')
                    try_find_second = re.compile(r'(\d{2}:\d{2}:\d{2})')
                    good_format_time = try_find.findall(extracted)
                    good_format_second = try_find_second.findall(extracted)
                    for gft in good_format_time:
                        _3_first_matches.append(gft)
                    for gfs in good_format_second:
                        _3_last_matches.append(gfs)

                count = 0
                final_time_list = []
                if _3_first_matches:
                    for _3 in _3_first_matches:
                        split_3_parts = _3_first_matches[count].split('/')
                        day = split_3_parts[0]
                        month = split_3_parts[1]
                        year = split_3_parts[2]
                        month_update = month_map[month]
                        formated_proper_date = year + '-' + month_update + '-' + day
                        final_time_list.append(formated_proper_date)
                        count = count + 1

                _get_mid_date_ = []
                if final_time_list:
                    print(Colors.yellow(f"[*] Working on {date.today().year} only..."))
                    for final in final_time_list:
                        get_year = int(final.split('-')[0])
                        if get_year == date.today().year:
                            _get_mid_date_.append(final)

                full_date = []
                for first, second in zip(_get_mid_date_, _3_last_matches):
                    full_date.append(first + ':' + second)

                month_extractor = []
                day_extractor = []
                for full in full_date:
                    match_it = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                    match_it_2 = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                    if match_it:
                        month_extractor.append(match_it.groups(1))
                    if match_it_2:
                        day_extractor.append(match_it_2.groups(1) + ':' + match_it_2.groups(2))

                month_mapper = {
                    '01': 'January', '02': 'February', '03': 'March', '04': 'April',
                    '05': 'May', '06': 'June', '07': 'July', '08': 'August',
                    '09': 'September', '10': 'October', '11': 'November', '12': 'December'
                }

                work_up_day = []
                get_most_month = Counter(month_extractor).most_common(1)[0][0]
                change_month = month_mapper.get(get_most_month[1], get_most_month[1])
                print(Colors.green(f"[+] {change_month} Appears to be the most busy month...."))
                for d in day_extractor:
                    if get_most_month[1] in d:
                        work_up_day.append(d)

                busy_day = []
                if work_up_day:
                    for w in work_up_day:
                        match_repeated_day = re.match(r'\d\d', w)
                        if match_repeated_day:
                            busy_day.append(w)
                match_most_busy_day = Counter(busy_day).most_common(5)

                while len(match_most_busy_day) < 5:
                    match_most_busy_day.append(('N/A', 0))

                print(Colors.green(f"""
                            [+] Within Month: {change_month}
                            The Three Most Busy Days appears to be in the Logs:
                                    {match_most_busy_day[0]} #1
                                    {match_most_busy_day[1]} #2
                                    {match_most_busy_day[2]} #3
                                    {match_most_busy_day[3]} #4
                                    {match_most_busy_day[4]} #5
                        """))

                get_back_content = []
                for c in content.splitlines():
                    get_back_content.append(c)
                count = 0
                for g in get_most:
                    ip_add = g[0]
                    for get in get_back_content:
                        match_all_specifically_day1 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[0][0]))})', get)
                        match_all_specifically_day2 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[1][0]))})', get)
                        match_all_specifically_day3 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[2][0]))})', get)
                        match_all_specifically_day4 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[3][0]))})', get)
                        match_all_specifically_day5 = re.match(rf'^({re.escape(ip_add)}) - - \[({re.escape(str(match_most_busy_day[4][0]))})', get)
                        if match_all_specifically_day1:
                            print(Colors.cyan(f"""[+] {g} Appears to be in the 1st most busy day from 
                                                                    {change_month} - Which Busy Month from the Logs...."""))
                        if match_all_specifically_day2:
                            print(Colors.cyan(f"""[+] {g} Appears to be in the 2nd most busy day from 
                                                                    {change_month} - Which Busy Month from the Logs...."""))
                        if match_all_specifically_day3:
                            print(Colors.cyan(f"""[+] {g} Appears to be in the 3rd most busy day from 
                                                                    {change_month} - Which Busy Month from the Logs...."""))
                        if match_all_specifically_day4:
                            print(Colors.cyan(f"""[+] {g} Appears to be in the 4th most busy day from 
                                                                    {change_month} - Which Busy Month from the Logs...."""))
                        if match_all_specifically_day5:
                            print(Colors.cyan(f"""[+] {g} Appears to be in the 5th most busy day from 
                                                                    {change_month} - Which Busy Month from the Logs...."""))

                    count += 1

            ask_checking_ip_from_attacks = input(Colors.green(f"""[*] Do you want to check any of the IPS in the attack"
                                                                      pattern logs:         (yes/no)""")).lower()
            print(ask_checking_ip_from_attacks)

            if ask_checking_ip_from_attacks == 'yes':
                print(Colors.yellow(f"[*] Running VirusTotal lookup on top IPs..."))
                for ip, count in get_most:
                    print(Colors.cyan(f"\n[*] Querying: {ip}"))
                    result = request_reputation(f"https://{ip}")
                    if result:
                        if result['malicious'] > 0:
                            print(Colors.red(f"  [!] MALICIOUS — {result['malicious']} detections"))
                        elif result['suspicious'] > 0:
                            print(Colors.orange(f"  [!] SUSPICIOUS — {result['suspicious']} flags"))
                        else:
                            print(Colors.green(
                                f"  [+] Clean — Harmless: {result['harmless']} | Undetected: {result['Undetected']}"))

            if ask_checking_ip_from_attacks == 'no':
                print(Colors.yellow("[*] Skipping IP reputation check."))

    else:
        print(Colors.yellow(f"Unrecognized Choice: Check Menu\n {webserver_choice}"))
        sys.exit(1)


webserver_logs('access.log')
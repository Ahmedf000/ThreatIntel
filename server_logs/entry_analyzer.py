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


                    if match_lines_logs.group(3):
                        """Working with http method attack patterns"""
                        print(Colors.yellow(f"[*] Analyzing HTTP REQUEST Attack Patterns if any...."))
                        print(Colors.yellow(f"[*] Checking for SQL Injection patterns...."))
                        sqli_patterns = SQLi_decode_cond(match_lines_logs.group(3))

                        move_to_next = input("Enter to move to next pattern")
                        print(move_to_next)

                        print(Colors.yellow(f"[*] Checking for Command injection patterns...."))

                """get MOST repeated IP"""
                ips = []
                print(Colors.yellow(f"[*] Checking for The Most repeated IP...."))
                for line in content.splitlines():
                    match = re.match(pattern_logs, line)
                    if match:
                        ips.append(match.group(1))

                get_most = Counter(ips).most_common(5)
                """work with the most repeated IP"""


                extracted_all = []
                get_thefull_log = re.findall(f"{get_most}.*?", content)
                for get_full in get_thefull_log:
                    get_time_fromip = re.match(pattern_logs, get_full).group(2)
                    strip_off_time = re.findall(f"\d\d/\w\w\w/\d\d\d\d:\d\d:\d\d:\d\d", get_time_fromip)
                    extracted_all.append(get_time_fromip)

                """get working with the times frame for the most repeated IP"""
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
                        good_format_time = try_find.findall(extracted[count])
                        good_format_second = try_find_second.findall(extracted[count])
                        for good_format_time in good_format_time:
                            _3_first_matches.append(good_format_time)
                        for good_format_second in good_format_second:
                            _3_last_matches.append(good_format_second)

                        count += 1
                    """Work with this"""
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
                            # today = datetime.date.today()
                            count = count + 1

                    _get_mid_date_ = []
                    if final_time_list:
                        print(Colors.yellow(f"[*] Working on {date.today().year} only..."))
                        for final in final_time_list:
                            get_year = int(final.split('-')[0])
                            """if get_year == 2022:  # hardcode to test
                                _get_mid_date_.append(final)"""
                            if get_year == date.today().year:
                                _get_mid_date_.append(final)

                    full_date = []
                    for first, second in zip(_get_mid_date_, _3_last_matches):
                        full_date.append(first + ':' + second)

                    month_extractor = []
                    for full in full_date:
                        match_it = re.match(r'^(\d{4})-(\d{2})-(\d{2})', full)
                        if match_it:
                            month_extractor.append(match_it.groups(1))

                    get_most_month = Counter(month_extractor).most_common(1)[0][0]
                    for get in get_most_month:
                        if get_most_month in full_date:
                            pass






    elif webserver_choice == str(2):
        pass

    elif webserver_choice == str(3):
        pass

    else:
        print(Colors.yellow(f"Unrecognized Choice: Check Menu\n {choices_menu}"))
        sys.exit(1)
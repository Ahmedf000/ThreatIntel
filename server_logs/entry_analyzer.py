from collections import Counter
import os
import subprocess
import platform
import re
from colors.color import Colors
import requests
import argparse

import sys
import json



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
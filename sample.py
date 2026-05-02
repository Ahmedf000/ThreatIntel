import itertools

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
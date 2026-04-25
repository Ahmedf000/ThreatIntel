import re
from urllib.parse import unquote
from colors.color import Colors



def command_Injection_patterns(param):


    BASIC_INTRO = [
        "cat /etc/passwd",
        "`cat / etc / passwd`",
        "$(cat / etc / passwd)",
        "cat${IFS}/etc/passwd",
        "ls${IFS}-la",
        "ls;",
        ";ls",
        ";cat",
        "cat;",
        "/bin/sh",
        "/bin/bash",
        "/bin/zsh",
        "/dev/tcp/",
        "bash -c",
        "bash -i",
        "$'uname\\",
        """
        $ cat /et\
        c/pa\
        sswd
        """,
        "cat%20/et%5C%0Ac/pa%5C%0Asswd",
        "echo",
        "echo;",
        ";echo",
        "time if [",
        "/etc/passwd",
        "/passwd",
        "/etc"
        "passwd",
        "etc",
        "() { :;}; /bin/bash",
        "/bin"
        "/bash",
        "bin",
        "bash",
        "/usr/bin"
    ]


    MULTPLE_CMD = [
        "||",
        "&&",
        "|",
        "&"
    ]


    ARGS = [
        """ssh '-o"""
    ]


    CURL = ["curl",
            "http",
            "curl http",
            "-o"
            ".php"
    ]


    RAW_HEX = [
        "636174202f6574632f706173737764",
        "60636174202f20657463202f2070617373776460",
        "2428636174202f20657463202f2070617373776429",
        "636174247b4946537d2f6574632f706173737764",
        "6c73247b4946537d2d6c61",
        "6c733b",
        "3b6c73",
        "3b636174",
        "6361743b",
        "2f62696e2f7368",
        "2f62696e2f62617368",
        "2f62696e2f7a7368",
        "2f6465762f7463702f",
        "62617368202d63",
        "62617368202d69",
        "2427756e616d655c",
        "0a20202020202020202420636174202f65745c0a2020202020202020632f70615c0a2020202020202020737377640a2020202020202020",
        "6361742532302f6574253543253041632f706125354325304173737764",
        "6563686f",
        "6563686f3b",
        "3b6563686f"
    ]


    HEX_ESCAPED = [
        "\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
        "\\x60\\x63\\x61\\x74\\x20\\x2f\\x20\\x65\\x74\\x63\\x20\\x2f\\x20\\x70\\x61\\x73\\x73\\x77\\x64\\x60",
        "\\x24\\x28\\x63\\x61\\x74\\x20\\x2f\\x20\\x65\\x74\\x63\\x20\\x2f\\x20\\x70\\x61\\x73\\x73\\x77\\x64\\x29",
        "\\x63\\x61\\x74\\x24\\x7b\\x49\\x46\\x53\\x7d\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
        "\\x6c\\x73\\x24\\x7b\\x49\\x46\\x53\\x7d\\x2d\\x6c\\x61",
        "\\x6c\\x73\\x3b",
        "\\x3b\\x6c\\x73",
        "\\x3b\\x63\\x61\\x74",
        "\\x63\\x61\\x74\\x3b",
        "\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68",
        "\\x2f\\x62\\x69\\x6e\\x2f\\x62\\x61\\x73\\x68",
        "\\x2f\\x62\\x69\\x6e\\x2f\\x7a\\x73\\x68",
        "\\x2f\\x64\\x65\\x76\\x2f\\x74\\x63\\x70\\x2f",
        "\\x62\\x61\\x73\\x68\\x20\\x2d\\x63",
        "\\x62\\x61\\x73\\x68\\x20\\x2d\\x69",
        "\\x24\\x27\\x75\\x6e\\x61\\x6d\\x65\\x5c",
        "\\x0a\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x24\\x20\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x5c\\x0a\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x63\\x2f\\x70\\x61\\x5c\\x0a\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x73\\x73\\x77\\x64\\x0a\\x20\\x20\\x20\\x20\\x20\\x20\\x20\\x20",
        "\\x63\\x61\\x74\\x25\\x32\\x30\\x2f\\x65\\x74\\x25\\x35\\x43\\x25\\x30\\x41\\x63\\x2f\\x70\\x61\\x25\\x35\\x43\\x25\\x30\\x41\\x73\\x73\\x77\\x64",
        "\\x65\\x63\\x68\\x6f",
        "\\x65\\x63\\x68\\x6f\\x3b",
        "\\x3b\\x65\\x63\\x68\\x6f",
        "echo -e",
        "xxd",
        "`echo $'cat\\x",
        "xxd -r -p <<<",
        "cat `xxd ",
        "xxd -r -ps <(echo",
        "xxd;",
        ";xxd"
    ]


    SINGLE_QUOTES = [
        "w'h'o'am'i",
        "wh''oami",
        "'w'hoami",
        "c'at",
        "ca't",
        "l's"
    ]


    BRACES_BYPASS = [
        "{, ip, a}",
        "{, ifconfig}",
        "{, ifconfig, eth0}",
        "{l, -lh}",
        "s",
        "{, echo, ",
        '{,$"whoami",}',
        "echo ~-",
        "echo ~+",
        "echo ${HOME:0:1}",
        "cat ${HOME:0:1}etc${HOME:0:1}passwd",
        "${HOME:",
        "| tr",
        "\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
        "/\\b\\i\n/////s\\h",
        "who$()ami",
        "/ehhh/hmtc/pahhh/hmsswd",
    ]


    DNS_EX = [
        "; do host",
        '"$i.',
        "nslookup",
        "nslookup $(",
        "dig",
        "host",
        "host \\id",
        "dig +short",
        '-Command "IEX (nslookup'
    ]



    TECHNIQUES_MAP = {
        "KEYWORD CMD INJECTION": BASIC_INTRO,
        "MULTIPLE COMMANDS INJECTION": MULTPLE_CMD,
        "SSH PATTERN": ARGS,
        "CURLING PATTERNS": CURL,
        "RAW HEXADECIMAL PATTERNS": RAW_HEX,
        "ESCAPED HEXADECIMAL PATTERNS": HEX_ESCAPED,
        "SINGLE QUOTES BYPASSING": SINGLE_QUOTES,
        "BYPASSING WITH {} BRACES": BRACES_BYPASS,
        "DNS EXFILTRATION AND COMMAND INJECTION": DNS_EX,
    }

    hits = []
    for info, patterns in TECHNIQUES_MAP.items():
        for pattern in patterns:
            if pattern in param:
                hits.append((info, pattern))
                break

    if hits:
        for tech, matched in hits:
            print(Colors.red(f"[!] DETECTED: {tech} — matched: '{matched}'"))
    else:
        print(Colors.green("[✓] Clean"))

    return hits



def decode_encode(params):

    if params != unquote(params):
        decode_logs = unquote(params)
        print("[*] Logs Now Decoded, Perfoming pattern matching")
        analyse_pattern = command_Injection_patterns(params)
        return analyse_pattern


    else:
        print("[*] The Logs Already decoded and readable, Perfoming pattern matching")
        analyse_pattern = command_Injection_patterns(params)
        return analyse_pattern



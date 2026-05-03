import argparse
import sys
from colors.color import Colors
from phisher.email_header_analyser import email_header
from server_logs.entry_analyzer import webserver_logs
from phisher.js_integration import javascript_ioc


def main():
    ASCII = r"""                                                                                                                                                                                                                                       
             _____ _                    _    _____       _       _ 
            /__   \ |__  _ __ ___  __ _| |_  \_   \_ __ | |_ ___| |
              / /\/ '_ \| '__/ _ \/ _` | __|  / /\/ '_ \| __/ _ \ |
             / /  | | | | | |  __/ (_| | |_/\/ /_ | | | | ||  __/ |
             \/   |_| |_|_|  \___|\__,_|\__\____/ |_| |_|\__\___|_| V.1.0                                                                                                                                                                                                                                    
    """
    print(Colors.blue(ASCII))
    parser = argparse.ArgumentParser(description="""A tool to analyze phishing emails header with Js integration,
    And WebServer Logs """)
    parser.add_argument("-e", "--email", help="Analyse email headers -- Enter your argument with ' ' ")
    parser.add_argument("-j", "--js_integration", help="Analyse JS Script within Source code of the email")
    parser.add_argument("-w", "--webserver_logs", help="Analyse web server logs for IOCs")
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    if args.email:
        email_header(str(args.email))

    if args.js_integration:
        javascript_ioc(str(args.js_integration))

    if args.webserver_logs:
        webserver_logs(args.webserver_logs)


if __name__ == '__main__':
    main()
import zipfile
from email.parser import Parser
from email.policy import default
import os
import subprocess
import platform
import re
import email
from email import policy, message_from_file
from pathlib import Path
import argparse
import sys
import json
import quopri
from phisher.requestor_VT import request_reputation
from colors.color import Colors


FREE_MAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'icloud.com', 'protonmail.com', 'proton.me', 'aol.com', 'mail.com',
    'zoho.com', 'yandex.com', 'gmx.com', 'tutanota.com', 'fastmail.com',
    'mail.ru', 'inbox.com', 'ymail.com', 'msn.com', 'qq.com'
}


def _resolve_eml(file):
    candidate = os.path.expanduser(str(file).strip())
    if candidate.endswith('.eml'):
        candidate = candidate[:-4]

    def try_path(p):
        full = Path(str(p) + '.eml')
        return full if full.exists() else None

    found = try_path(candidate)
    if found:
        return str(found)

    found = try_path(Path.cwd() / Path(candidate).name)
    if found:
        return str(found)

    found = try_path(Path.home() / 'Desktop' / Path(candidate).name)
    if found:
        return str(found)

    raise FileNotFoundError(
        f"[!] Could not find '{Path(candidate).name}.eml' — "
        f"tried: given path, {Path.cwd()}, and {Path.home() / 'Desktop'}."
    )


def _extract_domain(value):
    if not value or value == 'N/A':
        return None
    match = re.search(r'@([\w.\-]+)', value)
    if not match:
        return None
    return match.group(1).strip('>').lower()


def _normalize_domain(domain):
    if not domain:
        return None
    parts = domain.rstrip('>').rstrip('.').split('.')
    if len(parts) >= 2:
        return parts[-2] + '.' + parts[-1]
    return domain


def _decode_qp_body(content):
    try:
        return quopri.decodestring(content.encode()).decode('utf-8', errors='replace')
    except Exception:
        return content


def _extract_urls_from_body(content):
    decoded = _decode_qp_body(content)
    cleaned = re.sub(r'=\n', '', decoded)
    cleaned = cleaned.replace('=3D', '=').replace('=3d', '=')
    urls = re.findall(r'https?://[^\s<>"\')\]]+', cleaned)
    clean = []
    for u in urls:
        u = u.rstrip('.,;)')
        if u not in clean:
            clean.append(u)
    return clean


def _extract_received_ips(content):
    received_headers = re.findall(r'^Received:.*?(?=\n\S|\Z)', content, re.MULTILINE | re.DOTALL)
    ips = []
    for r in received_headers:
        found = re.findall(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', r)
        for ip in found:
            if ip not in ips and not ip.startswith('127.') and not ip.startswith('10.') and not ip.startswith('192.168.'):
                ips.append(ip)
    return ips


def attachement_analyzer(file):
    eml_path = _resolve_eml(file)

    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        msg = email.message_from_file(f, policy=policy.default)

    attachments = []
    if not msg.walk():
        print("No attachments found")
        return

    pathcheck = Path('extracted_attachment')
    pathcheck.mkdir(parents=True, exist_ok=True)

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None:
            continue

        get_filename = part.get_filename()
        if get_filename:
            file_name = re.sub(r'[\\/*?:"<>|]', "", get_filename)
            payload = part.get_payload(decode=True)
            if payload:
                attachments.append((get_filename, payload))

        if attachments:
            with zipfile.ZipFile("attachments.zip", 'w') as zipf:
                for filename, data in attachments:
                    zipf.writestr(filename, data)
            print(f'Extracted {len(attachments)} files to attachments.zip')
        else:
            print('No attachments found')


def email_header(file):
    eml_path = _resolve_eml(file)

    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    if not content.strip():
        print(Colors.red("[!] The .eml file is empty — nothing to analyse."))
        return

    headers = Parser(policy=default).parsestr(content)
    deliveredto_ = headers['Delivered-To']
    return_      = headers['Return-Path']
    from_        = headers['From']
    to_          = headers['To']
    reply_to     = headers['Reply-To']

    subject_          = headers['Subject']          or 'N/A'
    date_             = headers['Date']             or 'N/A'
    message_id_       = headers['Message-ID']       or 'N/A'
    x_mailer_         = headers['X-Mailer']         or headers['User-Agent'] or 'N/A'
    content_type_     = headers['Content-Type']     or 'N/A'
    x_originating_ip_ = headers['X-Originating-IP'] or 'N/A'
    x_spam_status_    = headers['X-Spam-Status']    or 'N/A'
    x_spam_score_     = headers['X-Spam-Score']     or 'N/A'
    mime_version_     = headers['MIME-Version']      or 'N/A'

    if not return_:
        print(Colors.yellow("[!] Return-Path doesn't exist!"))
    if not reply_to:
        print(Colors.yellow("[!] Reply-To doesn't exist!"))

    headers_list = [
        deliveredto_ or 'N/A',
        return_      or 'N/A',
        from_        or 'N/A',
        to_          or 'N/A',
        reply_to     or 'N/A'
    ]

    cleaned_headers_list = []

    for header in headers_list:
        if header == 'N/A':
            cleaned_headers_list.append('N/A')
            continue
        if '<' not in header:
            cleaned_headers_list.append(header)
            continue
        match_re = re.search(r'<(.+?)>', header)
        if match_re:
            cleaned_headers_list.append(match_re.group(1))
        else:
            cleaned_headers_list.append(header)

    print(cleaned_headers_list)
    name_4_convenience = [
        'Delivered-To',
        'Return-Path',
        'From',
        'To',
        'Reply-To'
    ]

    print(Colors.bold("\n[+] Email Header Analysis"))
    print("─" * 60)
    for raw_email, name_4_con in zip(cleaned_headers_list, name_4_convenience):
        if raw_email and raw_email != 'N/A':
            print(Colors.blue(f"  {name_4_con:<18}: {raw_email}"))
        else:
            print(Colors.yellow(f"  {name_4_con:<18}: Not present"))

    print(Colors.bold("\n[+] Extended Header Fields"))
    print("─" * 60)
    print(Colors.blue(f"  {'Subject':<18}: {subject_}"))
    print(Colors.blue(f"  {'Date':<18}: {date_}"))
    print(Colors.blue(f"  {'Message-ID':<18}: {message_id_}"))
    print(Colors.blue(f"  {'X-Mailer':<18}: {x_mailer_}"))
    print(Colors.blue(f"  {'Content-Type':<18}: {content_type_}"))
    print(Colors.blue(f"  {'MIME-Version':<18}: {mime_version_}"))
    if x_originating_ip_ != 'N/A':
        print(Colors.orange(f"  {'X-Originating-IP':<18}: {x_originating_ip_}"))
    if x_spam_status_ != 'N/A':
        color = Colors.red if 'yes' in x_spam_status_.lower() else Colors.green
        print(color(f"  {'X-Spam-Status':<18}: {x_spam_status_}"))
    if x_spam_score_ != 'N/A':
        print(Colors.blue(f"  {'X-Spam-Score':<18}: {x_spam_score_}"))

    received_ips = _extract_received_ips(content)
    if received_ips:
        print(Colors.bold("\n[+] Received Chain — Origin IPs"))
        print("─" * 60)
        for idx, ip in enumerate(received_ips):
            print(Colors.cyan(f"  Hop {idx+1}: {ip}"))
    else:
        print(Colors.yellow("\n[!] No public IPs found in Received chain."))

    body_urls = _extract_urls_from_body(content)
    if body_urls:
        print(Colors.bold("\n[+] URLs found in email body (incl. quoted-printable decoded)"))
        print("─" * 60)
        for u in body_urls:
            print(Colors.orange(f"  [URL] {u}"))
    else:
        print(Colors.yellow("\n[!] No URLs found in email body."))

    print("\n")
    print(Colors.yellow("[*] Starting contextual analysis..."))
    print(Colors.yellow("[*] Comparing Reply-to and From emails...."))

    scoring_system = 0

    from_val   = cleaned_headers_list[2] if len(cleaned_headers_list) > 2 else 'N/A'
    reply_val  = cleaned_headers_list[4] if len(cleaned_headers_list) > 4 else 'N/A'
    return_val = cleaned_headers_list[1] if len(cleaned_headers_list) > 1 else 'N/A'

    from_domain   = _extract_domain(from_val)
    reply_domain  = _extract_domain(reply_val)
    return_domain = _extract_domain(return_val)

    if from_domain and from_domain in FREE_MAIL_DOMAINS:
        print(Colors.orange(f"[!] From domain is a free mail provider ({from_domain})."))
        print(Colors.orange(f"    Anyone can register — treat with caution regardless of auth results."))
        scoring_system -= 10

    if from_domain and reply_domain:
        from_parser     = from_val.split('@')
        reply_to_parser = reply_val.split('@')

        from_dom_clean  = _normalize_domain(from_parser[1])
        reply_dom_clean = _normalize_domain(reply_to_parser[1])

        if from_dom_clean != reply_dom_clean:
            scoring_system = 0
            print(Colors.red(f"""
                    \u26a0\ufe0f UUhh!
                    The From & Reply-to not matching..
                    Please check:
                    {from_dom_clean}
                    {reply_dom_clean}
                    with scoring system {scoring_system} As we prefer it NULL.
                """))
        else:
            scoring_system += 20
            print(Colors.green(f"[+] Both From & Reply-to matching. Awesome :)"))
            print(Colors.blue(f"Scoring system up to {scoring_system}."))
    else:
        print(Colors.yellow("[!] Skipping From/Reply-To comparison — one or both headers missing."))

    print("\n")
    print(Colors.cyan("Moving to next contextual analysis..."))

    if return_val != 'N/A':
        getdkim_ = re.compile(r'Authentication-Results:.*?(?=\n\S)', re.DOTALL)
        dkim_block = getdkim_.search(content)

        if not dkim_block:
            print(Colors.yellow("[!] No Authentication-Results header found — skipping DKIM/SPF/DMARC."))
            scoring_system -= 30
        else:
            matchdkim_ = dkim_block.group()
            print(Colors.blue("Running the analysis...\n"))

            getdkim_rule_ = re.compile(r'dkim=\S+', re.IGNORECASE)
            dkim_hit      = getdkim_rule_.search(matchdkim_)
            getdkim_match_ = dkim_hit.group() if dkim_hit else None

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
                    print(Colors.red(f""" ===== \u26a0\ufe0f UUHHH ======
                        The DKIM Signature is {check_dkim_pass[1]} is not valid
                        Scoring system is now {scoring_system}...
                        """))
            else:
                scoring_system -= 20
                print(Colors.red("[!] DKIM Signature not found...."))
                print(Colors.red(f"Score is down to {scoring_system}."))

            if return_domain and from_domain:
                get_return_domain = re.search(r'@[\w.\-]+', return_val)
                get_from_domain   = re.search(r'@[\w.\-]+', from_val)

                if get_return_domain and get_from_domain:
                    join_get_pure_return_domain = _normalize_domain(get_return_domain.group().lstrip('@'))
                    join_get_pure_from_domain   = _normalize_domain(get_from_domain.group().lstrip('@'))

                    getto_comparison = input(Colors.yellow("Press Enter to move to Return-Path & Path comparison.."))
                    print(getto_comparison)
                    if join_get_pure_return_domain == join_get_pure_from_domain:
                        scoring_system += 15
                        print(Colors.green("""[+] Both From & Return-Path domain matches..."""))
                        print(Colors.blue(f"Great indicator...now scoring system up to {scoring_system}\n"))
                    else:
                        print(Colors.red(f"""\u26a0\ufe0f UUUHHH - The From & Return-Path domains are not match please check...
                    {join_get_pure_return_domain}
                    {join_get_pure_from_domain}
                    """))
                        scoring_system = scoring_system - 15
                else:
                    print(Colors.yellow("[!] Could not parse Return-Path or From domain."))
                    scoring_system -= 15
            else:
                print(Colors.yellow("[!] Skipping Return-Path/From comparison — missing domain info."))
                scoring_system -= 15

            getdmarc_rule_ = re.compile(r'dmarc=\S+', re.IGNORECASE)
            dmarc_hit      = getdmarc_rule_.search(matchdkim_)
            getdmarc_match_ = dmarc_hit.group() if dmarc_hit else None

            getto_dmarc = input(Colors.yellow("Press Enter to move to DMARC analysis...."))
            print(getto_dmarc)
            if getdmarc_match_:
                check_dmarc_pass = getdmarc_match_.split('=')
                if check_dmarc_pass[1].lower() == 'pass':
                    scoring_system += 10
                    print(Colors.green(f"[+] DMARC is {check_dmarc_pass[1]}"))
                    print(Colors.blue(f"[+] Score is set up now to {scoring_system}\n"))
                else:
                    scoring_system -= 10
                    print(Colors.red(f""" ===== \u26a0\ufe0f UUHHH ======
                        The DMARC Signature is {check_dmarc_pass[1]} is not valid
                        Scoring system is now {scoring_system}...
                        """))
            else:
                scoring_system -= 10
                print(Colors.red("[!] DMARC Signature not found...."))
                print(Colors.red(f"Score is down to {scoring_system}."))

            getspf_rule_ = re.compile(r'spf=\S+', re.IGNORECASE)
            spf_hit      = getspf_rule_.search(matchdkim_)
            getspf_match_ = spf_hit.group() if spf_hit else None

            getto_spf = input(Colors.yellow("Press Enter to move to SPF analysis...."))
            print(getto_spf)
            if getspf_match_:
                check_spf_pass = getspf_match_.split('=')
                if check_spf_pass[1].lower() == 'pass':
                    scoring_system += 15
                    print(Colors.green(f"[+] SPF is {check_spf_pass[1]}"))
                    print(Colors.blue(f"Scoring system is having great score up to {scoring_system}"))
                else:
                    scoring_system -= 10
                    print(Colors.red(f""" ===== \u26a0\ufe0f UUHHH ======
                        The SPF Signature is {check_spf_pass[1]} is not valid
                        Scoring system is now {scoring_system}...
                        """))
            else:
                scoring_system -= 10
                print(Colors.red("[!] SPF Signature not found...."))
                print(Colors.red(f"Score is down to {scoring_system}."))
    else:
        print(Colors.yellow("[!] Return-Path missing — skipping DKIM/SPF/DMARC block."))
        scoring_system -= 30

    suggest_further_request = input(Colors.yellow("Do you want to query Virus Total (yes / no):    ")).lower()
    print(suggest_further_request)

    if suggest_further_request == 'yes':
        print(Colors.yellow("[*] Extracting DKIM d= paramter and From Domain before..."))
        getdomains_  = re.compile(r'Authentication-Results:.*?(?=\n\S)', re.DOTALL)
        domain_block = getdomains_.search(content)

        if not domain_block:
            print(Colors.yellow("[!] No Authentication-Results found — cannot extract domain for VT lookup."))
        elif not from_domain:
            print(Colors.yellow("[!] From header missing — cannot run VT lookup."))
        else:
            matchdomain        = domain_block.group()
            get_thedomain      = re.compile(r'@[\w.\-]+', re.IGNORECASE)
            match_thedomain    = get_thedomain.search(matchdomain)
            match_thedomain_from = get_thedomain.search(from_val)

            if not match_thedomain or not match_thedomain_from:
                print(Colors.yellow("[!] Could not extract domain — skipping VT lookup."))
            else:
                strip_at_from_domain   = match_thedomain.group().lstrip('@')
                strip_at_from_domain_2 = match_thedomain_from.group().lstrip('@')

                if strip_at_from_domain_2 == strip_at_from_domain:
                    print(Colors.yellow(f"""
                    Both From & DKIM Domain matches...
                    {strip_at_from_domain_2}
                    {strip_at_from_domain}
                    """))

                run_the_request = request_reputation(f"https://{strip_at_from_domain_2}")
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
                else:
                    print(Colors.yellow("[!] VT lookup returned no result."))

        if body_urls:
            vt_body = input(Colors.yellow("\n[*] Also run VT on URLs found in email body? (yes/no):  ")).lower()
            print(vt_body)
            if vt_body == 'yes':
                for body_url in body_urls:
                    print(Colors.cyan(f"\n[*] Querying VT for: {body_url}"))
                    result = request_reputation(body_url)
                    if result:
                        m = result['malicious']
                        s = result['suspicious']
                        h = result['harmless']
                        u = result['Undetected']
                        if m > 0:
                            print(Colors.red(f"[!] MALICIOUS — {m} detections: {body_url}"))
                            scoring_system -= 20
                        elif s > 0:
                            print(Colors.orange(f"[!] SUSPICIOUS — {s} flags: {body_url}"))
                            scoring_system -= 10
                        else:
                            print(Colors.green(f"[+] Clean — Harmless: {h} | Undetected: {u}"))
                    else:
                        print(Colors.yellow(f"[!] No result for {body_url}"))

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

    attachement_analyzer(file)
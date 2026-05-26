import zipfile
import os
import re
import email
import quopri
from email.parser import Parser
from email.policy import default as _ep_default
from email import policy as _ep
from pathlib import Path
from dotenv import load_dotenv

from phisher.requestor_VT import request_reputation
from colors.color import Colors

load_dotenv()

FREE_MAIL_DOMAINS = {
    'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
    'icloud.com', 'protonmail.com', 'proton.me', 'aol.com', 'mail.com',
    'zoho.com', 'yandex.com', 'gmx.com', 'tutanota.com', 'fastmail.com',
    'mail.ru', 'inbox.com', 'ymail.com', 'msn.com', 'qq.com',
}


# ── Path resolver ─────────────────────────────────────────────────
def _resolve_eml(file: str) -> str:
    candidate = os.path.expanduser(str(file).strip())
    if candidate.endswith('.eml'):
        candidate = candidate[:-4]

    def _try(p):
        full = Path(str(p) + '.eml')
        return full if full.exists() else None

    for base in [
        Path(candidate),
        Path.cwd() / Path(candidate).name,
        Path.home() / 'Desktop' / Path(candidate).name,
        Path('/root/Desktop') / Path(candidate).name,
    ]:
        found = _try(base)
        if found:
            return str(found)

    raise FileNotFoundError(
        f"[!] Could not find '{Path(candidate).name}.eml' — "
        f"tried: given path, {Path.cwd()}, {Path.home() / 'Desktop'}, /root/Desktop"
    )


# ── Domain helpers ────────────────────────────────────────────────
def _extract_domain(value: str) -> str | None:
    if not value or value in ('N/A', ''):
        return None
    m = re.search(r'@([\w.\-]+)', value)
    return m.group(1).strip('>').lower() if m else None


def _normalize_domain(domain: str) -> str | None:
    if not domain:
        return None
    parts = domain.rstrip('>.').split('.')
    return (parts[-2] + '.' + parts[-1]) if len(parts) >= 2 else domain


def _strip_angle(value: str) -> str:
    """Return the address inside <…>, or the raw value if no brackets."""
    if not value:
        return 'N/A'
    m = re.search(r'<([^>]+)>', str(value))
    return m.group(1).strip() if m else str(value).strip()


# ── Multi-address extraction ──────────────────────────────────────
def _all_addresses_from_string(raw: str) -> list[str]:
    """
    Given a header value that may contain multiple addresses like
      "Alice" <alice@x.com>, bob@y.com
    return every unique email address found.
    """
    if not raw or raw == 'N/A':
        return []
    # prefer <addr> style
    angle = re.findall(r'<([^>]+@[^>]+)>', raw)
    if angle:
        return [a.strip().lower() for a in angle]
    # fall back to bare addr@domain
    return [a.lower() for a in re.findall(r'[\w.+\-]+@[\w.\-]+', raw)]


def _extract_all_recipients(
        raw_content: str,
        headers,
) -> list[tuple[str, str]]:
    """
    Return [(header_name, address), …] for every recipient found across:
      To, CC, BCC, Delivered-To (all occurrences), X-Forwarded-To, X-Original-To
    Addresses deduplicated case-insensitively.
    """
    seen:  set[str]              = set()
    result: list[tuple[str,str]] = []

    def _add(hdr: str, raw: str):
        for addr in _all_addresses_from_string(raw):
            if addr not in seen:
                seen.add(addr)
                result.append((hdr, addr))

    # Parsed headers (handles folded lines correctly)
    for hdr in ('To', 'CC', 'BCC', 'X-Forwarded-To', 'X-Original-To'):
        val = headers[hdr]
        if val:
            _add(hdr, str(val))

    # Raw scan — catches repeated Delivered-To / X-Forwarded-To lines
    # and multi-value To/CC that the simple parser might miss
    HDR_RE = re.compile(
        r'^(To|CC|BCC|Delivered-To|X-Forwarded-To|X-Original-To)'
        r':\s*(.*?)(?=\n\S|\Z)',
        re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    for m in HDR_RE.finditer(raw_content):
        _add(m.group(1), m.group(2).strip())

    return result


# ── IP extraction from Received chain ────────────────────────────
def _extract_received_ips(content: str) -> list[tuple[int, str]]:
    """Returns [(hop_index, ip), …] skipping RFC-1918 / loopback."""
    headers = re.findall(
        r'^Received:.*?(?=\n\S|\Z)', content, re.MULTILINE | re.DOTALL
    )
    result: list[tuple[int,str]] = []
    seen: set[str] = set()
    for idx, hdr in enumerate(headers, 1):
        for ip in re.findall(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', hdr):
            if (ip not in seen
                    and not ip.startswith('127.')
                    and not ip.startswith('10.')
                    and not ip.startswith('192.168.')
                    and not re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip)):
                seen.add(ip)
                result.append((idx, ip))
    return result


# ── Body URL extraction ───────────────────────────────────────────
def _extract_urls_from_body(content: str) -> list[str]:
    try:
        decoded = quopri.decodestring(content.encode()).decode('utf-8', errors='replace')
    except Exception:
        decoded = content
    cleaned = re.sub(r'=\n', '', decoded).replace('=3D', '=').replace('=3d', '=')
    seen:   set[str]  = set()
    result: list[str] = []
    for u in re.findall(r'https?://[^\s<>"\')\]]+', cleaned):
        u = u.rstrip('.,;)')
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


# ── Verdict printer ───────────────────────────────────────────────
def _print_verdict(score: int):
    print(Colors.bold(f"\n{'═'*60}"))
    print(Colors.bold(f"  FINAL LEGITIMACY SCORE : {score}"))
    print(Colors.bold(f"{'═'*60}"))
    if score >= 90:
        print(Colors.green( f"  [✓] STRONG LEGITIMACY — very likely genuine"))
    elif score >= 50:
        print(Colors.cyan(  f"  [~] MOSTLY LEGITIMATE — minor concerns"))
    elif score >= 30:
        print(Colors.orange(f"  [!] SUSPICIOUS — review carefully"))
    else:
        print(Colors.red(   f"  [!!!] HIGH PHISHING LIKELIHOOD"))
    print(Colors.bold(f"{'═'*60}\n"))


# ── VT helpers ────────────────────────────────────────────────────
def _print_vt_result(vt: dict):
    url_ = vt['url']
    m, s, h, u = vt['malicious'], vt['suspicious'], vt['harmless'], vt['Undetected']
    if m > 0 and s > 0:
        print(Colors.red(   f"  [!!!] MALICIOUS ({m}) + SUSPICIOUS ({s}) — {url_}"))
    elif m > 0:
        print(Colors.red(   f"  [!]   MALICIOUS: {m} detection(s) — {url_}"))
    elif s > 0:
        print(Colors.orange(f"  [!]   SUSPICIOUS: {s} flag(s) — {url_}"))
    else:
        print(Colors.green( f"  [✓]   Clean — Harmless:{h}  Undetected:{u} — {url_}"))
    if url_.startswith('http://'):
        print(Colors.orange(f"  [!]   HTTP-only, no SSL — phishing indicator"))


def _apply_vt_score(vt: dict, score: int) -> int:
    m, s = vt['malicious'], vt['suspicious']
    if m > 0 and s > 0: return score - 50
    if m > 0:           return score - 30
    if s > 0:           return score - 15
    return score + 10


# ── Attachment analyser (rewritten) ──────────────────────────────
def attachment_analyzer(file: str):
    print(Colors.bold(f"\n[+] Attachment Analysis"))
    print("─" * 60)

    eml_path = Path(_resolve_eml(file))
    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        msg = email.message_from_file(f, policy=_ep.default)

    attachments: list[tuple[str, bytes]] = []

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue

        disposition = str(part.get('Content-Disposition') or '')
        filename    = part.get_filename()

        # Accept explicit attachments OR any part carrying a filename
        if 'attachment' not in disposition.lower() and not filename:
            continue

        if not filename:
            ext      = part.get_content_subtype() or 'bin'
            filename = f"attachment_{len(attachments)+1}.{ext}"

        safe_name = re.sub(r'[\\/*?:"<>|]', '_', filename)
        payload   = part.get_payload(decode=True)

        if payload:
            attachments.append((safe_name, payload))
            print(Colors.cyan(f"  [+] Found: {safe_name}  ({len(payload):,} bytes)  "
                              f"[{part.get_content_type()}]"))

    if not attachments:
        print(Colors.yellow("  [!] No attachments found."))
        return

    # Write zip ONCE, AFTER collecting all parts (original wrote inside loop)
    zip_path = eml_path.parent / (eml_path.stem + '_attachments.zip')
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in attachments:
            zf.writestr(name, data)

    print(Colors.green(f"\n  [+] {len(attachments)} file(s) → {zip_path}"))
    print(Colors.red("  [!] DO NOT open attachments outside a sandbox."))


# ── Main ──────────────────────────────────────────────────────────
def email_header(file: str):
    eml_path = _resolve_eml(file)

    with open(eml_path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    if not content.strip():
        print(Colors.red("[!] The .eml file is empty."))
        return

    headers = Parser(policy=_ep_default).parsestr(content)

    # ── Raw header values ─────────────────────────────────────────
    from_raw      = str(headers['From']       or 'N/A')
    return_raw    = str(headers['Return-Path']or 'N/A')
    reply_to_raw  = str(headers['Reply-To']   or 'N/A')
    delivered_to  = str(headers['Delivered-To']or 'N/A')

    subject_      = str(headers['Subject']          or 'N/A')
    date_         = str(headers['Date']             or 'N/A')
    message_id_   = str(headers['Message-ID']       or 'N/A')
    x_mailer_     = str(headers['X-Mailer'] or headers['User-Agent'] or 'N/A')
    content_type_ = str(headers['Content-Type']     or 'N/A')
    x_orig_ip_    = str(headers['X-Originating-IP'] or 'N/A')
    x_spam_stat_  = str(headers['X-Spam-Status']    or 'N/A')
    x_spam_scr_   = str(headers['X-Spam-Score']     or 'N/A')
    mime_ver_     = str(headers['MIME-Version']      or 'N/A')

    from_clean    = _strip_angle(from_raw)
    return_clean  = _strip_angle(return_raw)
    replyto_clean = _strip_angle(reply_to_raw)

    # ── All recipients ────────────────────────────────────────────
    all_recipients = _extract_all_recipients(content, headers)

    # ── Received chain IPs ────────────────────────────────────────
    received_ips = _extract_received_ips(content)

    # ── Body URLs ─────────────────────────────────────────────────
    body_urls = _extract_urls_from_body(content)



    print(Colors.bold("             EMAIL HEADER ANALYSIS                      "))

    # Core headers
    print(Colors.bold("\n[+] Core Headers"))
    print("─" * 60)
    def _pf(name, val, color=Colors.blue):
        print(color(f"  {name:<22}: {val}"))

    _pf("From",         from_clean)
    _pf("Return-Path",  return_clean)
    _pf("Reply-To",
        replyto_clean if replyto_clean != 'N/A' else "(not present)",
        Colors.yellow if replyto_clean == 'N/A' else Colors.blue)
    _pf("Delivered-To", delivered_to)

    # Warn if Reply-To is absent — common in phishing (uses From for replies
    # but some phishing kits omit it to look clean)
    if replyto_clean == 'N/A':
        print(Colors.yellow("  [!] Reply-To header is absent."))

    # ── ALL recipients ────────────────────────────────────────────
    print(Colors.bold(f"\n[+] All Recipients  ({len(all_recipients)} unique address(es))"))
    print("─" * 60)
    if all_recipients:
        for hdr_name, addr in all_recipients:
            print(Colors.cyan(f"  {hdr_name:<22}: {addr}"))
    else:
        print(Colors.yellow("  [!] No recipient addresses could be extracted."))

    # Extended fields
    print(Colors.bold("\n[+] Extended Header Fields"))
    print("─" * 60)
    _pf("Subject",      subject_)
    _pf("Date",         date_)
    _pf("Message-ID",   message_id_)
    _pf("X-Mailer",     x_mailer_)
    _pf("Content-Type", content_type_)
    _pf("MIME-Version", mime_ver_)
    if x_orig_ip_ != 'N/A':
        _pf("X-Originating-IP", x_orig_ip_, Colors.orange)
    if x_spam_stat_ != 'N/A':
        c = Colors.red if 'yes' in x_spam_stat_.lower() else Colors.green
        _pf("X-Spam-Status", x_spam_stat_, c)
    if x_spam_scr_ != 'N/A':
        _pf("X-Spam-Score", x_spam_scr_)

    # ── Received chain ────────────────────────────────────────────
    print(Colors.bold("\n[+] Received Chain — Public Origin IPs"))
    print("─" * 60)
    if received_ips:
        for hop, ip in received_ips:
            print(Colors.cyan(f"  Hop {hop}: {ip}"))
        if x_orig_ip_ != 'N/A':
            known = {ip for _, ip in received_ips}
            if x_orig_ip_ not in known:
                print(Colors.orange(
                    f"  [!] X-Originating-IP {x_orig_ip_} is NOT in the Received chain "
                    f"— may indicate header forgery or internal relay."
                ))
    else:
        print(Colors.yellow("  [!] No public IPs found in Received headers."))
        if x_orig_ip_ != 'N/A':
            print(Colors.orange(f"  X-Originating-IP: {x_orig_ip_}"))

    # ── Body URLs ─────────────────────────────────────────────────
    print(Colors.bold("\n[+] URLs Found in Email Body"))
    print("─" * 60)
    if body_urls:
        for u in body_urls:
            print(Colors.orange(f"  [URL] {u}"))
    else:
        print(Colors.yellow("  [!] No URLs found in body."))

    # ════════════════════ SCORING ════════════════════════════════
    print(Colors.bold("\n[+] Authenticity Scoring"))
    print("─" * 60)
    score = 0

    from_domain     = _extract_domain(from_clean)
    replyto_domain  = _extract_domain(replyto_clean)
    return_domain   = _extract_domain(return_clean)

    # Free-mail check
    if from_domain and from_domain in FREE_MAIL_DOMAINS:
        print(Colors.orange(f"  [!] From domain is a free-mail provider ({from_domain}) → -10"))
        score -= 10

    # From vs Reply-To
    print(Colors.yellow("\n  [*] Checking From ↔ Reply-To…"))
    if from_domain and replyto_domain:
        fn = _normalize_domain(from_domain)
        rn = _normalize_domain(replyto_domain)
        if fn != rn:
            score = 0   # hard reset — textbook phishing tell
            print(Colors.red(f"  ⚠️  MISMATCH  From:{fn}  Reply-To:{rn}  → score reset to 0"))
        else:
            score += 20
            print(Colors.green(f"  [✓] From & Reply-To match ({fn}) → +20  (score {score})"))
    else:
        print(Colors.yellow("  [!] One or both headers missing — skipping comparison."))

    # Auth results block
    print(Colors.yellow("\n  [*] Parsing Authentication-Results…"))
    auth_m = re.search(r'Authentication-Results:.*?(?=\n\S|\Z)', content, re.DOTALL)

    if not auth_m:
        print(Colors.yellow("  [!] No Authentication-Results header found → -30"))
        score -= 30
    else:
        auth_block = auth_m.group()

        # DKIM
        input(Colors.yellow("  Press Enter → DKIM analysis…"))
        dkim_m = re.search(r'dkim=(\w+)', auth_block, re.IGNORECASE)
        if dkim_m:
            dval = dkim_m.group(1).lower()
            if dval == 'pass':
                score += 20
                print(Colors.green( f"  [✓] DKIM: {dval} → +20  (score {score})"))
            else:
                score -= 20
                print(Colors.red(   f"  [!] DKIM: {dval} → -20  (score {score})"))
        else:
            score -= 20
            print(Colors.red(f"  [!] DKIM: not found → -20  (score {score})"))

        # Return-Path vs From
        input(Colors.yellow("  Press Enter → Return-Path vs From comparison…"))
        if return_domain and from_domain:
            rn = _normalize_domain(return_domain)
            fn = _normalize_domain(from_domain)
            if rn == fn:
                score += 15
                print(Colors.green( f"  [✓] Return-Path & From match ({rn}) → +15  (score {score})"))
            else:
                score -= 15
                print(Colors.red(   f"  [!] Return-Path ({rn}) ≠ From ({fn}) → -15  (score {score})"))
        else:
            score -= 15
            print(Colors.yellow(f"  [!] Missing domain info → -15  (score {score})"))

        # DMARC
        input(Colors.yellow("  Press Enter → DMARC analysis…"))
        dmarc_m = re.search(r'dmarc=(\w+)', auth_block, re.IGNORECASE)
        if dmarc_m:
            dval = dmarc_m.group(1).lower()
            if dval == 'pass':
                score += 10
                print(Colors.green( f"  [✓] DMARC: {dval} → +10  (score {score})"))
            else:
                score -= 10
                print(Colors.red(   f"  [!] DMARC: {dval} → -10  (score {score})"))
        else:
            score -= 10
            print(Colors.red(f"  [!] DMARC: not found → -10  (score {score})"))

        # SPF
        input(Colors.yellow("  Press Enter → SPF analysis…"))
        spf_m = re.search(r'spf=(\w+)', auth_block, re.IGNORECASE)
        if spf_m:
            sval = spf_m.group(1).lower()
            if sval == 'pass':
                score += 15
                print(Colors.green( f"  [✓] SPF: {sval} → +15  (score {score})"))
            else:
                score -= 10
                print(Colors.red(   f"  [!] SPF: {sval} → -10  (score {score})"))
        else:
            score -= 10
            print(Colors.red(f"  [!] SPF: not found → -10  (score {score})"))

    # ── VirusTotal ────────────────────────────────────────────────
    print(Colors.bold("\n[+] VirusTotal Reputation Check"))
    print("─" * 60)
    do_vt = input(Colors.yellow("  Run VirusTotal checks? (yes/no): ")).strip().lower()

    if do_vt == 'yes':

        # From domain
        if from_domain:
            print(Colors.yellow(f"\n  [→] Checking From-domain: {from_domain}"))
            vt = request_reputation(from_domain)
            if vt:
                _print_vt_result(vt)
                score = _apply_vt_score(vt, score)
            else:
                print(Colors.yellow("  [!] No VT result for From-domain."))

        # Each IP in the Received chain
        if received_ips:
            do_ip = input(Colors.yellow("  Check each Received-chain IP on VT? (yes/no): ")).strip().lower()
            if do_ip == 'yes':
                for hop, ip in received_ips:
                    print(Colors.cyan(f"\n  [→] Hop {hop} IP: {ip}"))
                    vt = request_reputation(ip)   # bare IP — no https://
                    if vt:
                        _print_vt_result(vt)
                        score = _apply_vt_score(vt, score)
                    else:
                        print(Colors.yellow(f"  [!] No VT result for {ip}"))

        # Body URLs
        if body_urls:
            do_url = input(Colors.yellow("  Check body URLs on VT? (yes/no): ")).strip().lower()
            if do_url == 'yes':
                for url in body_urls:
                    print(Colors.cyan(f"\n  [→] URL: {url}"))
                    vt = request_reputation(url)
                    if vt:
                        _print_vt_result(vt)
                        score = _apply_vt_score(vt, score)
                    else:
                        print(Colors.yellow(f"  [!] No VT result for {url}"))
    else:
        print(Colors.yellow("  [*] Skipping VirusTotal."))

    # ── Final verdict printed ONCE ────────────────────────────────
    _print_verdict(score)

    # ── Attachments ───────────────────────────────────────────────
    attachment_analyzer(file)

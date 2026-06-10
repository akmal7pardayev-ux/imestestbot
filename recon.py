import json
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime


COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'dev',
    'test', 'stage', 'app', 'portal', 'vpn', 'remote', 'cpanel',
    'webmail', 'support', 'help', 'docs', 'status', 'cdn',
    'm', 'mobile', 'ns1', 'ns2', 'mx', 'smtp', 'pop3', 'imap',
    'git', 'jenkins', 'jira', 'confluence', 'wiki', 'cloud',
    'dashboard', 'login', 'register', 'pay', 'payment', 'secure',
]


RECORD_TYPES = {
    'A': socket.AF_INET,
    'AAAA': socket.AF_INET6,
    'MX': None,
    'NS': None,
    'TXT': None,
}


def log(msg):
    print(f'[{datetime.now().strftime("%H:%M:%S")}] {msg}')


def get_public_ip():
    try:
        req = urllib.request.Request('https://api.ipify.org', headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode().strip()
    except Exception:
        return 'Unknown'


def query_crtsh(domain):
    log(f'Querying crt.sh for {domain}...')
    subs = set()
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode())
            for entry in data:
                name = entry.get('name_value', '')
                for n in name.split('\n'):
                    n = n.strip().lower()
                    if n.endswith(f'.{domain}') and '*' not in n:
                        subs.add(n)
    except Exception as e:
        log(f'crt.sh error: {e}')
    return sorted(subs)


def brute_subdomains(domain):
    log('Brute-forcing common subdomains...')
    subs = set()
    for s in COMMON_SUBDOMAINS:
        sub = f'{s}.{domain}'
        try:
            socket.getaddrinfo(sub, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_CANONNAME)
            subs.add(sub)
        except socket.gaierror:
            pass
        except Exception:
            pass
    return sorted(subs)


def get_dns_records(domain):
    log('Resolving DNS records...')
    records = {}

    try:
        records['A'] = [addr[4][0] for addr in socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)]
    except Exception:
        records['A'] = []

    try:
        records['AAAA'] = [addr[4][0] for addr in socket.getaddrinfo(domain, 80, socket.AF_INET6, socket.SOCK_STREAM)]
    except Exception:
        records['AAAA'] = []

    try:
        records['CNAME'] = socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_CANONNAME)[0][3]
    except Exception:
        records['CNAME'] = 'None'

    return records


def probe_http(subdomain):
    result = {'url': '', 'status': 0, 'server': '', 'tech': [], 'title': ''}

    for proto in ['https', 'http']:
        url = f'{proto}://{subdomain}'
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                result['url'] = url
                result['status'] = r.status
                result['server'] = r.headers.get('Server', '')
                body = r.read(8192).decode('utf-8', errors='ignore')

                if '<title>' in body:
                    title = body.split('<title>')[1].split('</title>')[0].strip()[:80]
                    result['title'] = title

                tech = []
                sf = r.headers.get('X-Powered-By', '')
                if sf:
                    tech.append(sf)
                if 'cloudflare' in str(r.headers).lower():
                    tech.append('Cloudflare')
                if 'nginx' in str(r.headers).lower():
                    tech.append('Nginx')
                if 'apache' in str(r.headers).lower():
                    tech.append('Apache')
                if result['server']:
                    tech.insert(0, result['server'])
                result['tech'] = list(dict.fromkeys(tech))
                break
        except urllib.error.HTTPError as e:
            result['url'] = url
            result['status'] = e.code
            result['server'] = e.headers.get('Server', '') if e.headers else ''
            break
        except Exception:
            continue

    return result


def format_telegram_message(domain, ip, subs, dns, live_hosts):
    msg = f'<b>\U0001F50D Domain Recon Report</b>\n'
    msg += f'<b>Target:</b> <code>{domain}</code>\n'
    msg += f'<b>Your IP:</b> <code>{ip}</code>\n'
    msg += f'<b>Time:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n'

    msg += f'<b>\U0001F310 DNS Records</b>\n'
    if dns.get('A'):
        msg += f'A: <code>{", ".join(dns["A"])}</code>\n'
    if dns.get('AAAA'):
        msg += f'AAAA: <code>{", ".join(dns["AAAA"])}</code>\n'
    if dns.get('CNAME') and dns['CNAME'] != 'None':
        msg += f'CNAME: <code>{dns["CNAME"][0]}</code>\n'
    msg += '\n'

    total = len(subs)
    live = len(live_hosts)
    msg += f'<b>\U0001F4E1 Subdomains Found: {total}</b>\n'
    msg += f'<b>Live: {live}</b>\n\n'

    if live_hosts:
        msg += '<b>Live Hosts:</b>\n'
        for h in live_hosts[:15]:
            status_str = str(h['status'])
            if h['status'] == 200:
                status_str = f'\U00002705 {h["status"]}'
            elif 300 <= h['status'] < 400:
                status_str = f'\U0001F504 {h["status"]}'
            elif 400 <= h['status'] < 500:
                status_str = f'\U0000274C {h["status"]}'
            elif h['status'] == 0:
                status_str = '\U000026AB No response'
            tech_str = f' | {" | ".join(h["tech"][:3])}' if h['tech'] else ''
            title_str = f' | {h["title"]}' if h.get('title') else ''
            msg += f'{h["url"]} [{status_str}]{tech_str}{title_str}\n'

        if len(live_hosts) > 15:
            msg += f'... and {len(live_hosts) - 15} more\n'
    msg += '\n'

    if subs:
        msg += f'<b>All Subdomains ({total}):</b>\n'
        chunk = subs[:30]
        msg += ', '.join(chunk[:15])
        if len(chunk) > 15:
            msg += '\n' + ', '.join(chunk[15:])
        if total > 30:
            msg += f'\n... and {total - 30} more'

    return msg


def send_telegram(bot_token, chat_id, message):
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    data = urllib.parse.urlencode({
        'chat_id': chat_id,
        'text': message,
        'parse_mode': 'HTML',
        'disable_web_page_preview': 'true',
    }).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def main():
    domain = os.environ.get('TARGET_DOMAIN')
    bot_token = os.environ.get('BOT_TOKEN')
    chat_id = os.environ.get('CHAT_ID')

    if not domain:
        print('Usage: set TARGET_DOMAIN env var')
        sys.exit(1)

    if not bot_token or not chat_id:
        print('Missing BOT_TOKEN or CHAT_ID')
        sys.exit(1)

    log(f'Starting recon on {domain}')

    ip = get_public_ip()
    dns = get_dns_records(domain)
    crt_subs = query_crtsh(domain)
    brute_subs = brute_subdomains(domain)
    all_subs = sorted(set(crt_subs + brute_subs))

    log(f'Total subdomains: {len(all_subs)}')

    live_hosts = []
    for i, sub in enumerate(all_subs[:50], 1):
        result = probe_http(sub)
        if result['status']:
            live_hosts.append(result)
            log(f'  [{i}/{min(50, len(all_subs))}] {sub} -> {result["status"]}')
        else:
            log(f'  [{i}/{min(50, len(all_subs))}] {sub} -> no response')

    msg = format_telegram_message(domain, ip, all_subs, dns, live_hosts)

    if len(msg) > 4000:
        msg = msg[:4000] + '\n\n... (truncated)'

    send_telegram(bot_token, chat_id, msg)
    log('Report sent to Telegram!')


if __name__ == '__main__':
    main()

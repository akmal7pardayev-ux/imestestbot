import json
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime


socket.setdefaulttimeout(5)


COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop', 'dev',
    'test', 'stage', 'app', 'portal', 'vpn', 'remote', 'cpanel',
    'webmail', 'support', 'help', 'docs', 'status', 'cdn',
    'm', 'mobile', 'ns1', 'ns2', 'mx', 'smtp', 'pop3', 'imap',
    'git', 'jenkins', 'jira', 'confluence', 'wiki', 'cloud',
    'dashboard', 'login', 'direct', 'origin', 'direct.origin',
    'origin-www', 'origin-api', 'static', 'assets', 'img',
    'lb', 'loadbalancer', 'node', 'server', 'web',
    'backup', 'beta', 'dev-api', 'staging', 'prod',
    'ssh', 'rdp', 'remote-desktop', 'owa', 'exchange',
    'autodiscover', 'lyncdiscover', 'sip',
]

COMMON_PORTS = [22, 25, 80, 443, 993, 143, 8080, 8443, 3306, 5432, 3389, 5900, 9090]

EXCHANGE_PATHS = ['/owa/', '/ecp/', '/EWS/Exchange.asmx', '/autodiscover/autodiscover.xml',
                   '/Microsoft-Server-ActiveSync/', '/Rpc/', '/powershell/']
CF_RANGES = [
    ('103.21.244.0', '103.21.247.255'), ('103.22.200.0', '103.22.203.255'),
    ('103.31.4.0', '103.31.7.255'), ('104.16.0.0', '104.31.255.255'),
    ('108.162.192.0', '108.162.255.255'), ('131.0.72.0', '131.0.75.255'),
    ('141.101.64.0', '141.101.127.255'), ('162.158.0.0', '162.159.255.255'),
    ('172.64.0.0', '172.71.255.255'), ('173.245.48.0', '173.245.63.255'),
    ('188.114.96.0', '188.114.127.255'), ('190.93.240.0', '190.93.255.255'),
    ('197.234.240.0', '197.234.243.255'), ('198.41.128.0', '198.41.255.255'),
]


def log(msg):
    print(f'[{datetime.now().strftime("%H:%M:%S")}] {msg}')


def is_cf_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    ip_num = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(parts))
    for s, e in CF_RANGES:
        sn = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(s.split('.')))
        en = sum(int(o) << (8 * (3 - i)) for i, o in enumerate(e.split('.')))
        if sn <= ip_num <= en:
            return True
    return False


def resolve(host):
    try:
        return [addr[4][0] for addr in socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)]
    except Exception:
        return []


def check_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    except Exception:
        return False


def get_service(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((ip, port))
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()[:100]
        s.close()
        return banner
    except Exception:
        return ''


def http_get(url, timeout=8):
    req = urllib.request.Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode('utf-8', errors='ignore'), r.status, dict(r.headers)


def query_crtsh(domain):
    subs = set()
    try:
        body, _, _ = http_get(f'https://crt.sh/?q=%25.{domain}&output=json', timeout=15)
        for entry in json.loads(body):
            for name in entry.get('name_value', '').split('\n'):
                name = name.strip().lower()
                if name.endswith(f'.{domain}') and '*' not in name:
                    subs.add(name)
    except Exception as e:
        log(f'crt.sh: {e}')
    return sorted(subs)


def brute_subs(domain):
    subs = set()
    for s in COMMON_SUBDOMAINS:
        host = f'{s}.{domain}'
        try:
            socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
            subs.add(host)
        except Exception:
            pass
    return sorted(subs)


def probe_http(host):
    result = {'url': '', 'status': 0, 'server': '', 'title': '', 'tech': [], 'cf': False}
    for proto in ['https', 'http']:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f'{proto}://{host}', headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
                result['url'] = f'{proto}://{host}'
                result['status'] = r.status
                result['server'] = r.headers.get('Server', '')
                result['cf'] = bool(r.headers.get('CF-RAY'))
                body = r.read(4096).decode('utf-8', errors='ignore')
                if '<title>' in body:
                    result['title'] = body.split('<title>')[1].split('</title>')[0].strip()[:60]
                return result
        except urllib.error.HTTPError as e:
            result['url'] = f'{proto}://{host}'
            result['status'] = e.code
            result['server'] = e.headers.get('Server', '') if e.headers else ''
            result['cf'] = bool(e.headers.get('CF-RAY')) if e.headers else False
            return result
        except Exception:
            continue
    return result


def check_exchange(ip, subdomains):
    log('Checking for Exchange endpoints...')
    findings = []
    checked = set()
    candidates = [s for s in subdomains if any(k in s for k in ['mail', 'mx', 'owa', 'exchange', 'autodiscover', 'webmail', 'outlook', 'smtp', 'pop', 'imap', 'remote'])]
    candidates = candidates[:5] if candidates else []

    for host in [f'mail.{subdomains[0].split(".", 1)[1]}' if subdomains else ''] + candidates + ['mail', 'mx', 'webmail', 'owa', 'exchange', 'outlook', 'remote']:
        if not host or '.' not in host:
            continue
        if host in checked:
            continue
        checked.add(host)

        ips = resolve(host)
        if ip not in ips:
            continue

        for path in EXCHANGE_PATHS:
            try:
                url = f'https://{host}{path}'
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    body = r.read(1024).decode('utf-8', errors='ignore')
                    is_owa = 'logonForm' in body or 'Outlook' in body or 'owa' in body.lower()
                    is_ecp = 'ecp' in body.lower()
                    findings.append({'host': host, 'path': path, 'status': r.status, 'exchange': is_owa or is_ecp})
            except urllib.error.HTTPError as e:
                if e.code in [302, 401]:
                    findings.append({'host': host, 'path': path, 'status': e.code, 'exchange': True})
            except Exception:
                continue

    return findings


def format_report(domain, ip, dns, subs, live_hosts, open_ports, exchange, history):
    msg = f'\U0001F50D <b>Recon Report: {domain}</b>\n'
    msg += f'<b>Time:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n'
    msg += f'<b>Your IP:</b> <code>{ip}</code> (GitHub, not you)\n\n'

    msg += '<b>\U0001F310 DNS Records</b>\n'
    for rtype, vals in dns.items():
        if vals:
            msg += f'{rtype}: <code>{", ".join(str(v) for v in vals[:3])}</code>\n'
    msg += '\n'

    msg += f'<b>\U0001F4E1 Subdomains: {len(subs)}</b>\n\n'

    ips_seen = set()
    for h in live_hosts[:15]:
        ips_seen.update(h.get('resolved_ips', []))
    if ips_seen:
        real_ips = [i for i in ips_seen if not is_cf_ip(i)]
        msg += f'<b>Real IPs found ({len(real_ips)}):</b>\n'
        for i in real_ips:
            msg += f'<code>{i}</code>\n'
        msg += '\n'

    if open_ports:
        msg += '<b>\U0001F5A5 Open Ports:</b>\n'
        for ip_addr, p, info in open_ports:
            banner = f' - {info}' if info else ''
            msg += f'<code>{ip_addr}:{p}</code>{banner}\n'
        msg += '\n'

    if history:
        non_cf = [i for i in history if not is_cf_ip(i)]
        if non_cf:
            msg += '<b>\U0001F4DC Historical IPs (non-CF):</b>\n'
            for i in sorted(non_cf)[:5]:
                msg += f'<code>{i}</code>\n'
            msg += '\n'

    if exchange:
        msg += '<b>\U0001F4E8 Exchange Server Found!</b>\n'
        for f in exchange[:8]:
            cf = ' (CF)' if any(i in f['host'] for i in ['kundalik', 'payhip']) else ''
            msg += f'{f["host"]}{f["path"]} -> {f["status"]}{cf}\n'
        msg += '\n'

    if live_hosts:
        msg += '<b>Live hosts:</b>\n'
        for h in live_hosts[:10]:
            cf_tag = ' \U00002601' if h.get('cf') else ' \U00002705'
            msg += f'{h["url"]} [{h["status"]}]{cf_tag}\n'
        msg += '\n'

    if subs:
        msg += f'<b>Subdomains:</b>\n'
        chunk = subs[:20]
        msg += ', '.join(chunk[:10])
        if len(chunk) > 10:
            msg += '\n' + ', '.join(chunk[10:])
        if len(subs) > 20:
            msg += f'\n... +{len(subs) - 20} more'

    return msg


def send_telegram(bot_token, chat_id, text):
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    data = urllib.parse.urlencode({
        'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML',
        'disable_web_page_preview': 'true'
    }).encode()
    req = urllib.request.Request(url, data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10):
        pass


def main():
    domain = os.environ.get('TARGET_DOMAIN')
    bot_token = os.environ.get('BOT_TOKEN')
    chat_id = os.environ.get('CHAT_ID')

    if not domain:
        log('Missing TARGET_DOMAIN')
        sys.exit(1)

    log(f'Starting recon: {domain}')

    ip = ''
    try:
        ip = urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode()
    except Exception:
        pass

    dns_records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS']:
        try:
            _, _, addrs = socket.gethostbyname_ex(domain)
            if addrs:
                dns_records[rtype] = addrs[:3]
        except Exception:
            pass

    try:
        mx = socket.getaddrinfo(domain, 25, socket.AF_INET, socket.SOCK_STREAM)
        dns_records['MX'] = [addr[4][0] for addr in mx[:3]]
    except Exception:
        pass

    log('DNS done. Enumerating subdomains...')
    crt = query_crtsh(domain)
    brute = brute_subs(domain)
    all_subs = sorted(set(crt + brute))
    log(f'Subdomains: {len(all_subs)}')

    log('Probing HTTP...')
    live = []
    seen_ips = set()
    for sub in all_subs[:40]:
        info = probe_http(sub)
        ips = resolve(sub)
        info['resolved_ips'] = ips
        seen_ips.update(ips)
        if info['status']:
            live.append(info)
            log(f'  {sub} -> {info["status"]}')
        else:
            log(f'  {sub} -> no response')

    log('Checking ports on discovered IPs...')
    all_ips = set()
    for h in all_subs[:40]:
        all_ips.update(resolve(h))
    open_ports = []
    for target_ip in list(all_ips)[:5]:
        for port in COMMON_PORTS:
            if check_port(target_ip, port):
                svc = get_service(target_ip, port)
                open_ports.append((target_ip, port, svc))
                log(f'  {target_ip}:{port} open - {svc[:40]}')

    exchange = []
    for target_ip in list(all_ips)[:3]:
        ex = check_exchange(target_ip, all_subs)
        exchange.extend(ex)
        if ex:
            log(f'  Exchange found on {target_ip}')

    history = []
    try:
        body, _, _ = http_get(f'https://viewdns.info/iphistory/?domain={domain}', timeout=10)
        import re
        rows = re.findall(r'<tr><td>(\d+\.\d+\.\d+\.\d+)</td>', body)
        history = list(set(rows))
    except Exception:
        pass

    msg = format_report(domain, ip, dns_records, all_subs, live, open_ports, exchange, history)

    if len(msg) > 4000:
        msg = msg[:4000] + '\n\n... truncated'

    try:
        send_telegram(bot_token, chat_id, msg)
        log('Report sent!')
    except Exception as e:
        log(f'Failed to send report: {e}')


if __name__ == '__main__':
    main()

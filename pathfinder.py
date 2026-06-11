#!/usr/bin/env python3
"""
Pathfinder — simplified BloodHound for Linux privesc path discovery.
Usage: python3 pathfinder.py
"""
import json
import os
import pwd
import grp
import stat
import subprocess
import sys
from collections import defaultdict
from datetime import datetime


RESET = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'


def log(msg, level='info'):
    ts = datetime.now().strftime('%H:%M:%S')
    prefix = {'info': f'{CYAN}[*]{RESET}', 'good': f'{GREEN}[+]{RESET}',
              'bad': f'{RED}[-]{RESET}', 'warn': f'{YELLOW}[!]{RESET}'}.get(level, f'{CYAN}[*]{RESET}')
    print(f'{ts} {prefix} {msg}')


def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, shell=True)
        return r.stdout.strip()
    except:
        return ''


def get_current_user():
    return os.getenv('USER') or os.getenv('USERNAME') or run_cmd('whoami')


def get_groups(user):
    out = run_cmd(f'groups {user}')
    return out.replace(f'{user} : ', '').split() if out else []


def get_all_users():
    users = []
    with open('/etc/passwd') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 3 and int(parts[2]) >= 1000:
                users.append({'name': parts[0], 'uid': int(parts[2]), 'gid': int(parts[3]), 'home': parts[5], 'shell': parts[6]})
    return users


def check_sudo(user):
    out = run_cmd(f'sudo -l -U {user} 2>/dev/null')
    if not out or 'not allowed' in out.lower():
        return None
    rules = []
    for line in out.split('\n'):
        if '(' in line and ')' in line:
            rules.append(line.strip())
    return rules if rules else None


def find_suid():
    return run_cmd('find / -perm -4000 -type f 2>/dev/null').split('\n')


def find_capabilities():
    out = run_cmd('getcap -r / 2>/dev/null')
    return [l.strip() for l in out.split('\n') if l.strip()] if out else []


def check_writable_passwd():
    try:
        return os.access('/etc/passwd', os.W_OK)
    except:
        return False


def check_writable_shadow():
    try:
        return os.access('/etc/shadow', os.W_OK)
    except:
        return False


def check_writable_sudoers():
    sudoers_d = '/etc/sudoers.d'
    try:
        writable = []
        for f in os.listdir(sudoers_d):
            fp = os.path.join(sudoers_d, f)
            if os.access(fp, os.W_OK):
                writable.append(fp)
        return writable
    except:
        return []


def check_docker_group(groups):
    return 'docker' in groups


def check_lxd_group(groups):
    return 'lxd' in groups


def check_writable_cron():
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly', '/var/spool/cron/crontabs']
    writable = []
    for d in cron_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                if os.access(fp, os.W_OK):
                    writable.append(fp)
    return writable


def check_writable_scripts_in_path():
    paths = os.environ.get('PATH', '/usr/bin:/bin').split(':')
    writable = []
    for p in paths:
        if os.path.isdir(p) and os.access(p, os.W_OK):
            for f in os.listdir(p):
                fp = os.path.join(p, f)
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    writable.append(fp)
    return writable


def check_writable_service_files():
    systemd = '/etc/systemd/system'
    writable = []
    if os.path.isdir(systemd):
        for f in os.listdir(systemd):
            fp = os.path.join(systemd, f)
            if os.access(fp, os.W_OK):
                writable.append(fp)
    return writable


def check_nfs_no_root_squash():
    out = run_cmd('cat /etc/exports 2>/dev/null')
    if out:
        return [l.strip() for l in out.split('\n') if 'no_root_squash' in l]
    return []


def check_unmounted_disks():
    out = run_cmd('lsblk -o NAME,MOUNTPOINT,FSTYPE 2>/dev/null')
    unmounted = []
    for line in out.split('\n')[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == '':
            unmounted.append(parts[0])
    return unmounted


def check_path_wildcard(path='/tmp'):
    return run_cmd(f'ls -la {path} 2>/dev/null | head -20')


def check_kernel_version():
    return run_cmd('uname -r')


def analyze_paths(user, groups, all_users, sudo_rules, suid, caps, findings):
    paths = []

    # 1. Direct root via SUID
    suid_root = [f for f in suid if f]
    if suid_root:
        known_binaries = ['/usr/bin/pkexec', '/usr/bin/su', '/bin/su', '/usr/bin/sudo', '/bin/mount',
                          '/usr/bin/mount', '/usr/bin/umount', '/bin/umount', '/usr/bin/cp',
                          '/usr/bin/vim', '/usr/bin/nano', '/usr/bin/less', '/usr/bin/more',
                          '/usr/bin/man', '/usr/bin/python', '/usr/bin/python3', '/usr/bin/perl']
        dangerous = [f for f in suid_root if f in known_binaries]
        if dangerous:
            paths.append({
                'from': user, 'to': 'root', 'method': 'SUID binary exploitation',
                'detail': f'Dangerous SUID: {", ".join(dangerous)}',
                'severity': 'HIGH'
            })

    # 2. Sudo rules
    if sudo_rules:
        for rule in sudo_rules:
            if 'NOPASSWD' in rule or 'ALL' in rule:
                cmd = rule.split(')')[1].strip() if ')' in rule else rule
                paths.append({
                    'from': user, 'to': 'root', 'method': 'sudo',
                    'detail': f'sudo {cmd} (NOPASSWD or ALL)',
                    'severity': 'HIGH'
                })

    # 3. Docker group
    if 'docker' in groups:
        paths.append({
            'from': user, 'to': 'root', 'method': 'Docker group membership',
            'detail': 'docker run -v /:/mnt alpine chroot /mnt',
            'severity': 'HIGH'
        })

    # 4. LXD group
    if 'lxd' in groups:
        paths.append({
            'from': user, 'to': 'root', 'method': 'LXD group membership',
            'detail': 'lxd init + lxc launch ubuntu:18.04 + mount host root',
            'severity': 'HIGH'
        })

    # 5. Writable passwd
    for f in findings:
        if f['type'] == 'Writable /etc/passwd':
            paths.append({
                'from': user, 'to': 'root', 'method': 'Writable /etc/passwd',
                'detail': 'Remove root password: sed -i "s/root:x/root::/" /etc/passwd, then su',
                'severity': 'CRITICAL'
            })

    # 6. Writable shadow
    for f in findings:
        if f['type'] == 'Writable /etc/shadow':
            paths.append({
                'from': user, 'to': 'root', 'method': 'Writable /etc/shadow',
                'detail': 'Replace root hash with known password hash',
                'severity': 'CRITICAL'
            })

    # 7. Writable sudoers.d
    for f in findings:
        if f['type'] == 'Writable sudoers.d files':
            nodes = f['detail']
            paths.append({
                'from': user, 'to': 'root', 'method': 'Writable sudoers.d',
                'detail': f'Echo "{user} ALL=(ALL) NOPASSWD:ALL" > {nodes[0] if nodes else "/etc/sudoers.d/pwn"}',
                'severity': 'CRITICAL'
            })

    # 8. Writable cron
    cron_files = [f for f in findings if f['type'] == 'Writable cron files']
    if cron_files:
        for cf in cron_files:
            paths.append({
                'from': user, 'to': 'root', 'method': 'Writable cron job',
                'detail': f'Write malicious script to {cf["detail"][0]}',
                'severity': 'HIGH'
            })

    # 9. NFS no_root_squash
    nfs = [f for f in findings if f['type'] == 'NFS no_root_squash']
    if nfs:
        paths.append({
            'from': user, 'to': 'root', 'method': 'NFS no_root_squash',
            'detail': 'Mount remotely as root, create SUID binary',
            'severity': 'HIGH'
        })

    # 10. Capabilities
    dangerous_caps = ['cap_setuid+ep', 'cap_dac_override+ep', 'cap_sys_admin+ep']
    if caps:
        for c in caps:
            for dc in dangerous_caps:
                if dc in c:
                    paths.append({
                        'from': user, 'to': 'root', 'method': 'Dangerous capability',
                        'detail': c,
                        'severity': 'HIGH'
                    })

    # 11. Kernel exploits
    kernel = run_cmd('uname -r')
    known_exploits = {
        '2.6.' : 'CVE-2016-5195 (DirtyCow)',
        '3.0': 'CVE-2016-5195 (DirtyCow)',
        '3.1': 'CVE-2016-5195 (DirtyCow)',
        '3.2': 'CVE-2016-5195 (DirtyCow)',
        '3.8': 'CVE-2016-0728',
        '3.9': 'CVE-2016-0728',
        '3.10': 'CVE-2016-5195 (DirtyCow)',
        '4.0': 'CVE-2016-5195 (DirtyCow)',
        '4.4': 'CVE-2017-16995',
        '4.5': 'CVE-2017-16995',
        '4.6': 'CVE-2017-16995',
        '4.8': 'CVE-2017-16995',
        '4.10': 'CVE-2017-16995',
        '4.13': 'CVE-2017-16995',
        '4.14': 'CVE-2017-16995',
        '4.15': 'CVE-2019-13272',
        '5.0': 'CVE-2021-3493',
        '5.1': 'CVE-2021-3493',
        '5.2': 'CVE-2021-3493',
        '5.3': 'CVE-2021-3493',
        '5.4': 'CVE-2022-0847 (DirtyPipe)',
        '5.5': 'CVE-2022-0847 (DirtyPipe)',
        '5.6': 'CVE-2022-0847 (DirtyPipe)',
        '5.7': 'CVE-2022-0847 (DirtyPipe)',
        '5.8': 'CVE-2022-0847 (DirtyPipe)',
        '5.9': 'CVE-2022-0847 (DirtyPipe)',
        '5.10': 'CVE-2022-0847 (DirtyPipe)',
        '5.11': 'CVE-2022-0847 (DirtyPipe)',
        '5.12': 'CVE-2022-0847 (DirtyPipe)',
        '5.13': 'CVE-2022-0847 (DirtyPipe)',
        '5.14': 'CVE-2022-0847 (DirtyPipe)',
        '5.15': 'CVE-2022-0847 (DirtyPipe)',
        '5.16': 'CVE-2022-0847 (DirtyPipe)',
        '5.17': 'CVE-2022-0847 (DirtyPipe)',
    }
    for ver, exploit in known_exploits.items():
        if kernel.startswith(ver):
            paths.append({
                'from': user, 'to': 'root', 'method': f'Kernel exploit: {exploit}',
                'detail': f'Kernel {kernel} may be vulnerable to {exploit}',
                'severity': 'MEDIUM'
            })
            break

    return paths


def collect():
    user = get_current_user()
    log(f'Target user: {BOLD}{user}{RESET}')
    groups = get_groups(user)
    log(f'Groups: {", ".join(groups)}')
    kernel = run_cmd('uname -a')
    log(f'Kernel: {kernel.split()[2] if kernel else "unknown"}')

    findings = []
    log('Scanning for privilege escalation vectors...')

    suid = find_suid()
    if suid and suid[0]:
        findings.append({'type': 'SUID binaries', 'detail': suid, 'severity': 'info'})
        log(f'Found {len(suid)} SUID binaries', 'good')
    else:
        log('No SUID binaries found', 'info')

    sudo_rules = check_sudo(user)
    if sudo_rules:
        findings.append({'type': 'Sudo rules', 'detail': sudo_rules, 'severity': 'info'})
        log(f'Sudo rules: {len(sudo_rules)}', 'good')
        for r in sudo_rules:
            log(f'  {r}', 'good')
    else:
        log('No sudo rules', 'info')

    if check_docker_group(groups):
        findings.append({'type': 'Docker group', 'detail': 'User in docker group', 'severity': 'HIGH'})
        log('User in docker group -> root directly', 'bad')
    if check_lxd_group(groups):
        findings.append({'type': 'LXD group', 'detail': 'User in lxd group', 'severity': 'HIGH'})
        log('User in lxd group -> root via privilege escalation', 'bad')

    caps = find_capabilities()
    if caps:
        findings.append({'type': 'Capabilities', 'detail': caps, 'severity': 'info'})
        log(f'Found {len(caps)} capabilities', 'good')

    if check_writable_passwd():
        findings.append({'type': 'Writable /etc/passwd', 'detail': '/etc/passwd is writable!', 'severity': 'CRITICAL'})
        log('/etc/passwd is writable!', 'bad')
    if check_writable_shadow():
        findings.append({'type': 'Writable /etc/shadow', 'detail': '/etc/shadow is writable!', 'severity': 'CRITICAL'})
        log('/etc/shadow is writable!', 'bad')

    sudoers_write = check_writable_sudoers()
    if sudoers_write:
        findings.append({'type': 'Writable sudoers.d files', 'detail': sudoers_write, 'severity': 'CRITICAL'})
        log(f'Writable sudoers files: {sudoers_write}', 'bad')

    cron_write = check_writable_cron()
    if cron_write:
        findings.append({'type': 'Writable cron files', 'detail': cron_write, 'severity': 'HIGH'})
        log(f'Writable cron files: {cron_write}', 'bad')

    path_write = check_writable_scripts_in_path()
    if path_write:
        findings.append({'type': 'Writable scripts in PATH', 'detail': path_write, 'severity': 'HIGH'})

    svc_write = check_writable_service_files()
    if svc_write:
        findings.append({'type': 'Writable systemd files', 'detail': svc_write, 'severity': 'HIGH'})

    nfs = check_nfs_no_root_squash()
    if nfs:
        findings.append({'type': 'NFS no_root_squash', 'detail': nfs, 'severity': 'HIGH'})
        log(f'NFS exports with no_root_squash: {nfs}', 'bad')

    return user, groups, findings, sudo_rules, suid, caps


def print_paths(paths, user):
    if not paths:
        print(f'\n{BOLD}{GREEN}[+] No privilege escalation path found from {user} to root.{RESET}')
        return

    print(f'\n{BOLD}{RED}╔══ PRIVILEGE ESCALATION PATHS ══╗{RESET}')
    print(f'{BOLD}From: {user}{RESET}')
    print(f'{BOLD}To:   root{RESET}\n')

    for i, p in enumerate(paths, 1):
        sev_color = {'CRITICAL': f'{RED}{BOLD}', 'HIGH': f'{RED}', 'MEDIUM': f'{YELLOW}'}.get(p['severity'], '')
        print(f'{BOLD}{i}. {sev_color}[{p["severity"]}]{RESET} {p["method"]}')
        print(f'   {CYAN}Path{RESET}: {p["from"]} → {p["to"]}')
        print(f'   {CYAN}How{RESET}:  {p["detail"]}')
        print()

    print(f'{BOLD}╚{"═"*36}╝{RESET}')
    print(f'\n{YELLOW}Tip: Research each method on GTFOBins (https://gtfobins.github.io){RESET}')


def print_summary(findings, user, groups):
    print(f'\n{BOLD}{CYAN}╔══ COLLECTION SUMMARY ══╗{RESET}')
    print(f'{BOLD}User: {user}{RESET}')
    print(f'{BOLD}Groups: {", ".join(groups)}{RESET}')
    print(f'{BOLD}Findings: {len(findings)}{RESET}')
    print(f'{BOLD}╚{"═"*26}╝{RESET}')

    critical = [f for f in findings if f.get('severity') == 'CRITICAL']
    high = [f for f in findings if f.get('severity') == 'HIGH']
    if critical:
        print(f'\n{RED}{BOLD}CRITICAL ({len(critical)}):{RESET}')
        for f in critical:
            print(f'  {f["type"]}: {f["detail"] if isinstance(f["detail"], str) else len(f["detail"])} items')
    if high:
        print(f'\n{RED}HIGH ({len(high)}):{RESET}')
        for f in high:
            print(f'  {f["type"]}: {f["detail"] if isinstance(f["detail"], str) else len(f["detail"])} items')


def main():
    print(f'\n{BOLD}{CYAN}  Pathfinder — Linux Privesc Path Analyzer{RESET}')
    print(f'{CYAN}  Simplified BloodHound for terminal{RESET}\n')

    if os.geteuid() == 0:
        log('Running as root — no privesc needed', 'warn')

    user, groups, findings, sudo_rules, suid, caps = collect()
    print_summary(findings, user, groups)
    paths = analyze_paths(user, groups, None, sudo_rules, suid, caps, findings)
    print_paths(paths, user)

    save = input(f'\n{YELLOW}Save report to JSON? (y/n): {RESET}').lower()
    if save == 'y':
        report = {
            'target': user,
            'timestamp': datetime.now().isoformat(),
            'kernel': run_cmd('uname -a'),
            'findings': findings,
            'paths': paths
        }
        fname = f'pathfinder_{user}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(fname, 'w') as f:
            json.dump(report, f, indent=2)
        log(f'Saved: {fname}', 'good')


if __name__ == '__main__':
    main()

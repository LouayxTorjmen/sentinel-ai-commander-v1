#!/usr/bin/env python3
"""
Test all 9 Ansible playbooks by directly calling the Ansible Runner API.
Each playbook is invoked with realistic test parameters and a single
target host. Results saved to /tmp/sentinel_playbook_test/.

Strategy:
  - Use auto-victim1-ubuntu (192.168.49.128) as the primary target (it
    is reachable and responds to ansible ping).
  - Use kali-agent-1 (192.168.49.131) as the "attacker IP" in playbooks
    that need a source_ip parameter.
  - dry_run is set to false so we see real execution. After the run,
    each playbook's effect is described in the cleanup section so you
    can manually verify and revert.

Output:
  - Per-test status, rc, ok/changed/failed counts
  - Full JSON saved to /tmp/sentinel_playbook_test/
  - Cleanup hints printed at the end

Usage:
    python3 test_playbooks.py
"""
import json
import time
from pathlib import Path

import requests

OUT = Path("/tmp/sentinel_playbook_test")
OUT.mkdir(exist_ok=True)
for f in OUT.glob("*.json"):
    f.unlink()

ENDPOINT = "http://localhost:50011/run"
TARGET = "auto-victim1-ubuntu"
ATTACKER_IP = "192.168.49.131"
SEVERITY = "high"
TIMEOUT = 300  # per playbook

# Common defaults that every playbook may reference
def base_vars(extra=None):
    v = {
        "incident_id": f"test-{int(time.time())}",
        "severity": SEVERITY,
        "target_hosts": TARGET,
    }
    if extra:
        v.update(extra)
    return v


# Test cases: (id, playbook_name, extra_vars, what_it_does, cleanup_hint)
TESTS = [
    (
        "01_brute_force_response",
        "brute_force_response",
        base_vars({"source_ip": ATTACKER_IP}),
        "Block attacker IP, collect evidence, notify SOC",
        f"On {TARGET}: 'iptables -L SENTINEL_BLOCK -n' should show {ATTACKER_IP} DROP rule. "
        "Auto-unblocks in 1h via at-job; or run: iptables -D SENTINEL_BLOCK -s "
        f"{ATTACKER_IP} -j DROP",
    ),
    (
        "02_incident_response",
        "incident_response",
        base_vars({"source_ip": ATTACKER_IP}),
        "Generic catch-all: evidence + IP block + notify",
        f"Same as above. Also evidence in /tmp/sentinel_evidence/{base_vars()['incident_id']} on target.",
    ),
    (
        "03_fim_restore_response",
        "fim_restore_response",
        base_vars({"file_path": "/tmp/sentinel_test_fim.txt"}),
        "Restore a file from baseline. Will fail gracefully if file isn't in baseline.",
        f"On {TARGET}: check /tmp/sentinel_evidence/* for the run log. The actual "
        "restore is a no-op for a non-tracked path.",
    ),
    (
        "04_lateral_movement_response",
        "lateral_movement_response",
        base_vars({
            "source_ip": ATTACKER_IP,
            "dest_ip": "192.168.49.128",
        }),
        "Block both source AND destination IP, collect evidence",
        f"On {TARGET}: 'iptables -L SENTINEL_BLOCK -n' should show TWO rules. "
        "Both auto-unblock in 1h or remove manually.",
    ),
    (
        "05_compromised_user_response",
        "compromised_user_response",
        base_vars({"username": "sentineltestuser"}),
        "Disable a user account, kill their sessions, collect evidence",
        f"On {TARGET}: this will FAIL unless 'sentineltestuser' exists. To recover a real "
        "user: 'passwd -u <username>'.",
    ),
    # SKIPPED (dangerous, run separately):
    #     (
    #         "06_malware_containment",
    #         "malware_containment",
    #         base_vars({
    #             "source_ip": ATTACKER_IP,
    #             "malware_process": "definitely_not_a_real_process_xyz",
    #             "malware_pid": "0",
    #         }),
    #         "Isolate host (firewall lockdown), kill process, quarantine",
    #         f"DANGEROUS: isolates {TARGET} from the network except manager. "
    #         "If it succeeds, manual recovery: SSH from console, 'systemctl restart firewalld' "
    #         "or 'iptables -F'. Process kill will safely fail (no such process).",
    #     ),
    (
        "07_file_quarantine_response",
        "file_quarantine_response",
        base_vars({"file_path": "/tmp/sentinel_quarantine_test.txt"}),
        "Quarantine a file (chmod 000 + move + hash log)",
        f"On {TARGET}: check /tmp/sentinel_quarantine/. Original path will be empty. "
        "First create the test file: 'touch /tmp/sentinel_quarantine_test.txt'.",
    ),
    (
        "08_permissions_restore_response",
        "permissions_restore_response",
        base_vars({"custom_paths": ["/tmp/sentinel_perm_test"]}),
        "Reset permissions on a path",
        f"On {TARGET}: usually a no-op for /tmp paths. Will pass if path doesn't exist.",
    ),
    # SKIPPED (dangerous, run separately):
    #     (
    #         "09_vulnerability_patch",
    #         "vulnerability_patch",
    #         base_vars({
    #             "cve_id": "CVE-TEST-0000",
    #             "patch_packages": [],
    #         }),
    #         "Run apt update && apt upgrade (or dnf update) for security packages",
    #         f"DANGEROUS: actually installs security updates on {TARGET}. May reboot services. "
    #         "Pass empty patch_packages to skip OR limit blast radius via specific names.",
    #     ),
]


def run_test(tid, playbook, extra_vars):
    print(f"  POST /run playbook={playbook}")
    print(f"    target_hosts={extra_vars.get('target_hosts')}")
    print(f"    extra_vars={json.dumps({k: v for k, v in extra_vars.items() if k != 'target_hosts'})}")
    t0 = time.time()
    try:
        r = requests.post(
            ENDPOINT,
            json={"playbook": playbook, "extra_vars": extra_vars},
            timeout=TIMEOUT,
        )
    except requests.Timeout:
        return {"status": "timeout", "rc": -1, "elapsed": time.time() - t0}
    except Exception as exc:
        return {"status": "error", "rc": -1, "error": str(exc), "elapsed": time.time() - t0}

    elapsed = time.time() - t0

    try:
        data = r.json()
    except Exception:
        return {"status": "non-json", "rc": r.status_code, "body": r.text[:500], "elapsed": elapsed}

    data["elapsed"] = elapsed
    data["http_status"] = r.status_code
    return data


# ─── Run ─────────────────────────────────────────────────────────────

results = []

print("=" * 76)
print(f"Target host:  {TARGET}")
print(f"Attacker IP:  {ATTACKER_IP}")
print(f"Output dir:   {OUT}")
print("=" * 76)

for tid, playbook, vars_, what, cleanup in TESTS:
    print()
    print(f"[{tid}] {playbook}")
    print(f"  WHAT: {what}")
    res = run_test(tid, playbook, vars_)

    (OUT / f"{tid}.json").write_text(json.dumps(res, indent=2, default=str))

    status = res.get("status", "?")
    rc = res.get("rc", "?")
    stats = res.get("stats", {}) or {}
    ok = stats.get("ok", {})
    changed = stats.get("changed", {})
    failures = stats.get("failures", {})
    elapsed = res.get("elapsed", 0)

    if status == "successful" or rc == 0:
        verdict = "PASS"
    elif status == "timeout":
        verdict = f"TIMEOUT >{TIMEOUT}s"
    else:
        verdict = f"FAIL ({status} rc={rc})"

    print(f"  RESULT: {verdict}  elapsed={elapsed:.1f}s")
    print(f"    ok={ok} changed={changed} failures={failures}")
    print(f"  CLEANUP: {cleanup}")

    results.append({
        "id": tid,
        "playbook": playbook,
        "verdict": verdict,
        "rc": rc,
        "elapsed": elapsed,
        "ok": ok,
        "changed": changed,
        "failures": failures,
    })

# ─── Summary ─────────────────────────────────────────────────────────

print()
print("=" * 76)
print("SUMMARY")
print("=" * 76)
print(f"{'TEST':<35} {'VERDICT':<25} {'TIME':>8}")
print("-" * 76)
for r in results:
    print(f"{r['id']:<35} {r['verdict']:<25} {r['elapsed']:>6.1f}s")

n_pass = sum(1 for r in results if r["verdict"] == "PASS")
n_fail = len(results) - n_pass
print("-" * 76)
print(f"PASS: {n_pass}/{len(results)}  FAIL: {n_fail}")
print()
print(f"Full per-test JSON in: {OUT}/")
print()
print("CLEANUP CHECKLIST (manual on target):")
print(f"  ssh root@<target>")
print(f"  iptables -L SENTINEL_BLOCK -n      # any leftover blocks?")
print(f"  ls /tmp/sentinel_evidence/         # evidence dirs")
print(f"  ls /tmp/sentinel_quarantine/       # quarantined files")
print(f"  ls /var/log/sentinel-ai-responses.log")
print(f"  iptables -F SENTINEL_BLOCK         # clear all sentinel blocks")

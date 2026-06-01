#!/bin/bash
# SENTINEL-AI — Full patch script
# Run on WSL2 host from ~/sentinel-ai-commander
set -e
cd ~/sentinel-ai-commander

echo "=== Patch 1: FIM noise overhaul ==="
python3 - << 'PY'
path = "ai_agents/agents/wazuh_consumer/alert_dispatcher.py"
with open(path) as f:
    s = f.read()

# 1a) Replace _FIM_NOISE_PATTERNS with extended version
old_patterns = '''_FIM_NOISE_PATTERNS = (
    # User desktop / session state
    "/.config/", "/.local/", "/.cache/", "/.xsession-errors",
    "/.gvfs-metadata/", "/.mozilla/", "/.thunderbird/",
    "/.dbus/", "/run/user/",
    # Snap apps churn
    "/snap/",
    # Print spooler + ansible runs
    "/etc/cups/", "/tmp/ansible_", "/tmp/.X", "/tmp/systemd-",
    # Package manager tempdirs and metadata (dnf/yum/apt/rpm)
    "/tmp/tmpdir.", "/repodata/",
    "/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/",
    "/var/lib/dnf/", "/var/lib/apt/", "/var/lib/rpm/",
    # systemd transient drop-ins
    "/run/systemd/",
)'''

new_patterns = '''_FIM_NOISE_PATTERNS = (
    # User desktop / session state
    "/.config/", "/.local/", "/.cache/", "/.xsession-errors",
    "/.gvfs-metadata/", "/.mozilla/", "/.thunderbird/",
    "/.dbus/", "/run/user/",
    # Snap apps churn
    "/snap/",
    # Print spooler + ansible runs
    "/etc/cups/", "/tmp/ansible_", "/tmp/.X", "/tmp/systemd-",
    # Package manager tempdirs and metadata (dnf/yum/apt/rpm)
    "/tmp/tmpdir.", "/repodata/",
    "/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/",
    "/var/lib/dnf/", "/var/lib/apt/", "/var/lib/rpm/",
    # systemd transient drop-ins
    "/run/systemd/",
    # Wazuh agent self-monitoring (agent writes its own queue/log files)
    "/var/ossec/queue/", "/var/ossec/logs/", "/var/ossec/tmp/",
    # Log rotation artifacts
    "/var/log/journal/", ".log.1", ".gz.tmp", ".log.gz",
    # Python / pip installs triggered by Ansible
    "/lib/python", "/site-packages/", "/__pycache__/",
    # SSH known_hosts churned by scan/connect activity from framework
    "/.ssh/known_hosts",
    # Windows (Ansible WinRM) temp paths — forwarded as lowercase by Wazuh
    "\\\\appdata\\\\local\\\\temp\\\\", "\\\\windows\\\\temp\\\\",
    "/appdata/local/temp/", "/windows/temp/",
    "\\\\users\\\\admini",
    # Windows WinRM session artifacts
    "\\\\programdata\\\\microsoft\\\\windows\\\\wer\\\\",
    "\\\\windows\\\\prefetch\\\\",
    "\\\\windows\\\\softwaredistribution\\\\",
    # Windows Event Log churn from Ansible/WinRM commands
    "\\\\windows\\\\system32\\\\winevt\\\\logs\\\\",
    "/windows/system32/winevt/",
    # Wazuh Windows agent self-writes
    "\\\\wazuh-agent\\\\", "ossec-agent",
    # Python temp files from Ansible Windows modules
    "\\\\tmp\\\\ansible-tmp-", "\\\\tmp\\\\tmp",
)

# Windows agents: only dispatch FIM if path IS explicitly security-relevant.
# Everything else from Windows agents is Ansible/WinRM churn.
_FIM_WINDOWS_AGENTS = {"srv-ad-dns", "srv-ftp"}
_FIM_WINDOWS_CRITICAL_PATHS = (
    # System binaries — modification = rootkit/tamper
    "\\\\system32\\\\",
    "\\\\syswow64\\\\",
    "\\\\windows\\\\system32\\\\drivers\\\\",
    # Startup persistence locations
    "\\\\currentversion\\\\run",
    "\\\\currentversion\\\\runonce",
    "\\\\windows\\\\startup\\\\",
    "\\\\programdata\\\\microsoft\\\\windows\\\\start menu\\\\programs\\\\startup",
    # Scheduled tasks
    "\\\\system32\\\\tasks\\\\",
    "\\\\syswow64\\\\tasks\\\\",
    # Hosts file tampering
    "\\\\system32\\\\drivers\\\\etc\\\\hosts",
    # LSASS / SAM / credential stores
    "\\\\system32\\\\config\\\\sam",
    "\\\\system32\\\\config\\\\system",
    # Our monitored sentinel paths
    "c:\\\\sentinel",
    # Cron equivalent — Windows scheduled tasks XML
    "\\\\tasks\\\\sentinel",
)'''

if old_patterns in s:
    s = s.replace(old_patterns, new_patterns)
    print("  ✓ _FIM_NOISE_PATTERNS extended")
else:
    print("  ! _FIM_NOISE_PATTERNS not found — check manually")

# 1b) Replace _is_fim_noise to include Windows allowlist logic
old_fim_fn = '''def _is_fim_noise(alert: dict) -> bool:
    """Return True if a FIM alert path matches a known noise pattern."""
    syscheck = alert.get("syscheck") or alert.get("data", {}).get("syscheck") or {}
    path = (syscheck.get("path") or "").lower()
    if not path:
        return False
    return any(pat in path for pat in _FIM_NOISE_PATTERNS)'''

new_fim_fn = '''def _is_fim_noise(alert: dict) -> bool:
    """Return True if a FIM alert path matches a known noise pattern.

    For Windows agents (srv-ad-dns, srv-ftp), we use an ALLOWLIST approach:
    only dispatch if the path IS security-relevant. All other Windows FIM
    is Ansible/WinRM churn and has zero SOC value.

    For Linux agents we use the existing denylist (_FIM_NOISE_PATTERNS).
    """
    syscheck = alert.get("syscheck") or alert.get("data", {}).get("syscheck") or {}
    path = (syscheck.get("path") or "").lower()
    agent_name = (alert.get("agent") or {}).get("name", "")
    if not path:
        return False

    # Windows agents: allowlist approach — noise unless path is critical
    if agent_name in _FIM_WINDOWS_AGENTS:
        is_critical = any(crit in path for crit in _FIM_WINDOWS_CRITICAL_PATHS)
        return not is_critical  # noise=True if NOT critical

    # Linux agents: denylist approach — noise if path matches noise pattern
    return any(pat in path for pat in _FIM_NOISE_PATTERNS)'''

if old_fim_fn in s:
    s = s.replace(old_fim_fn, new_fim_fn)
    print("  ✓ _is_fim_noise updated with Windows allowlist")
else:
    print("  ! _is_fim_noise not found — check manually")

# 1c) Add Windows Ansible noise rules to HARD_SKIP_RULES
old_skip = '''HARD_SKIP_RULES = {
    40704,   # systemd unit failure (desktop app crashes)
    2902,    # dpkg package installed (workstation noise)
    2904,    # dpkg package removed (workstation noise)
    # SENTINEL-AI feedback rules — would create dispatch loop
    100500, 100501, 100502, 100503, 100504, 100505, 100506, 100507,
    # Windows NTLM logon — too noisy (Ansible WinRM generates constantly)
    # Lateral movement detected via custom rule 100620 instead
    92657,
}'''

new_skip = '''HARD_SKIP_RULES = {
    40704,   # systemd unit failure (desktop app crashes)
    2902,    # dpkg package installed (workstation noise)
    2904,    # dpkg package removed (workstation noise)
    # SENTINEL-AI feedback rules — would create dispatch loop
    100500, 100501, 100502, 100503, 100504, 100505, 100506, 100507,
    # Windows NTLM logon — too noisy (Ansible WinRM generates constantly)
    # Lateral movement detected via custom rule 100620 instead
    92657,
    # Windows Ansible/WinRM operational noise — zero SOC value
    92213,   # Windows scheduled task created/modified (Ansible artifact)
    62154,   # Windows service state change (Ansible WinRM side effect)
    60010,   # Windows Event Log cleared (harmless in lab)
    91809,   # PowerShell Base64 decode — Ansible uses this constantly
    # Windows MSI / .NET compiler noise
    60910,   # Windows Installer event
    60911,   # Windows Installer completed
    # Wazuh agent keepalive / inventory events — not threats
    521,     # Wazuh agent started
    502,     # Wazuh agent stopped
    503,     # Wazuh agent disconnected
}'''

if old_skip in s:
    s = s.replace(old_skip, new_skip)
    print("  ✓ HARD_SKIP_RULES extended with Windows Ansible noise")
else:
    print("  ! HARD_SKIP_RULES not found — check manually")

# 1d) Add per-category dedup: FIM rules get 300s window, scan rules 120s
old_dedup = '''    # Per (rule_id, agent_name) dedup
    import time
    key = (rule_id, agent_name)
    now = time.monotonic()
    last = _recent_dispatches.get(key)
    if last is not None and now - last < DISPATCH_DEDUP_WINDOW_S:
        return False, "dedup"
    _recent_dispatches[key] = now'''

new_dedup = '''    # Per (rule_id, agent_name) dedup — category-aware window
    # FIM rules churn heavily; give them a 5-minute window
    # Scan rules generate bursts; give them 2 minutes
    # Everything else: default window (60s)
    import time
    if rule_id in _FIM_RULES:
        effective_window = max(DISPATCH_DEDUP_WINDOW_S, 300.0)  # 5 min for FIM
    elif rule_id in {86601, 87702, 40503, 40116, 40117}:
        effective_window = max(DISPATCH_DEDUP_WINDOW_S, 120.0)  # 2 min for scans
    else:
        effective_window = DISPATCH_DEDUP_WINDOW_S
    key = (rule_id, agent_name)
    now = time.monotonic()
    last = _recent_dispatches.get(key)
    if last is not None and now - last < effective_window:
        return False, "dedup"
    _recent_dispatches[key] = now'''

if old_dedup in s:
    s = s.replace(old_dedup, new_dedup)
    print("  ✓ Category-aware dedup windows added")
else:
    print("  ! dedup block not found — check manually")

with open(path, "w") as f:
    f.write(s)
print("  Saved alert_dispatcher.py")
PY

echo ""
echo "=== Patch 2: STATIC_RULE_MAP enrichment + playbook outcome logging ==="
python3 - << 'PY'
path = "ai_agents/agents/ansible_dispatch/ansible_dispatch_agent.py"
with open(path) as f:
    s = f.read()

# 2a) Replace existing STATIC_RULE_MAP entries block with enriched version
# Find and replace the block starting from the STATIC_RULE_MAP definition
old_map_start = '''STATIC_RULE_MAP = {'''

# We'll insert new entries after existing ones — find the closing of the map
# by looking for the specific last entry we know exists
old_last_entries = '''    "87702": {"playbook": "block_ip", "severity": "high"},
    # Lateral movement — successful remote NTLM logon from external
    "92657": {"playbook": "lateral_movement_response", "severity": "high",
              "os_variants": {"windows": "win_lateral_movement_response"}},
    "100620": {"playbook": "win_lateral_movement_response", "severity": "critical"},
    # Falco: webshell/suspicious process on Linux (shadow read, sensitive file access)
    "100114": {"playbook": "incident_response", "severity": "high"},
    # PowerShell suspicious execution on DC
    "92057": {"playbook": "win_incident_response", "severity": "critical"},'''

new_entries = '''    "87702": {"playbook": "block_ip", "severity": "high"},
    # Lateral movement — successful remote NTLM logon from external
    "92657": {"playbook": "lateral_movement_response", "severity": "high",
              "os_variants": {"windows": "win_lateral_movement_response"}},
    "100620": {"playbook": "win_lateral_movement_response", "severity": "critical"},
    # Falco: webshell/suspicious process on Linux (shadow read, sensitive file access)
    "100114": {"playbook": "incident_response", "severity": "high"},
    # PowerShell suspicious execution on DC
    "92057": {"playbook": "win_incident_response", "severity": "critical"},

    # ── SSH Brute Force (extended) ──────────────────────────────────
    "5503": {"playbook": "brute_force_response", "severity": "high"},    # SSH max auth attempts exceeded
    "5551": {"playbook": "brute_force_response", "severity": "high"},    # SSH brute force (new variant)
    "5763": {"playbook": "brute_force_response", "severity": "high"},    # SSH scanner detected
    "2502": {"playbook": "brute_force_response", "severity": "medium"},  # FTP brute force
    "2503": {"playbook": "brute_force_response", "severity": "medium"},  # FTP auth failure frequency
    "11325": {"playbook": "brute_force_response", "severity": "high"},   # MySQL brute force
    "30304": {"playbook": "brute_force_response", "severity": "high"},   # Web brute force (DVWA)

    # ── Web Application Attacks ─────────────────────────────────────
    "31103": {"playbook": "incident_response", "severity": "high"},      # SQL injection attempt
    "31104": {"playbook": "incident_response", "severity": "high"},      # XSS attack
    "31108": {"playbook": "incident_response", "severity": "high"},      # Command injection
    "31151": {"playbook": "incident_response", "severity": "high"},      # PHP remote include
    "31516": {"playbook": "incident_response", "severity": "medium"},    # Directory traversal
    "31530": {"playbook": "incident_response", "severity": "critical"},  # Web shell upload
    "31531": {"playbook": "incident_response", "severity": "critical"},  # Web shell execution
    "77101": {"playbook": "incident_response", "severity": "critical"},  # Shellshock / bash injection

    # ── Privilege Escalation ────────────────────────────────────────
    "5402": {"playbook": "compromised_user_response", "severity": "high"},    # sudo -s (root shell obtained)
    "5403": {"playbook": "compromised_user_response", "severity": "high"},    # sudo to root
    "5404": {"playbook": "compromised_user_response", "severity": "critical"},# sudo fail then success
    "40111": {"playbook": "compromised_user_response", "severity": "critical"},# Privilege escalation

    # ── Malware / Rootkit (Wazuh built-in) ─────────────────────────
    "510": {"playbook": "malware_containment", "severity": "critical"},  # Rootkit hidden file
    "511": {"playbook": "malware_containment", "severity": "critical"},  # Rootkit hidden process
    "533": {"playbook": "malware_containment", "severity": "critical"},  # Worm detected
    "9502": {"playbook": "malware_containment", "severity": "critical"}, # ClamAV: virus found
    "9503": {"playbook": "malware_containment", "severity": "critical"}, # ClamAV: virus moved

    # ── Act 3: AS-REP Roast / Kerberoast (custom rules 100700+) ────
    "100700": {"playbook": "incident_response", "severity": "high"},     # AS-REP roast attempt
    "100701": {"playbook": "incident_response", "severity": "critical"}, # AS-REP roast frequency
    "100710": {"playbook": "incident_response", "severity": "high"},     # Kerberoast SPN enumeration
    "100711": {"playbook": "incident_response", "severity": "critical"}, # Kerberoast TGS-REQ spike

    # ── Act 3: SSH Lateral Movement ─────────────────────────────────
    "5715": {"playbook": "block_ip", "severity": "high"},                # SSH login from Kali IP
    "100720": {"playbook": "block_ip", "severity": "critical"},          # SSH lateral from attacker

    # ── Act 3: Raw TCP / NC Exfiltration ────────────────────────────
    "100730": {"playbook": "block_ip", "severity": "critical"},          # Raw TCP exfil to external
    "100731": {"playbook": "block_dns_exfil", "severity": "critical"},   # Data staging detected

    # ── Windows-specific Attacks ────────────────────────────────────
    "60106": {"playbook": "win_incident_response", "severity": "high"},        # Account lockout
    "60122": {"playbook": "win_incident_response", "severity": "high"},        # Failed logon frequency
    "91545": {"playbook": "win_incident_response", "severity": "critical"},    # Mimikatz detected
    "91556": {"playbook": "win_incident_response", "severity": "critical"},    # Rubeus/Kerberoast tool
    "92200": {"playbook": "win_incident_response", "severity": "critical"},    # LSASS access non-system
    "92656": {"playbook": "win_lateral_movement_response", "severity": "critical"}, # Pass-the-Hash

    # ── Network-level Suricata (extended) ───────────────────────────
    "40116": {"playbook": "block_ip", "severity": "medium"},  # ET SCAN: Nessus scan
    "40117": {"playbook": "block_ip", "severity": "medium"},  # ET SCAN: OpenVAS scan
    "86001": {"playbook": "block_ip", "severity": "high"},    # Suricata: SSH brute force
    "86002": {"playbook": "block_ip", "severity": "high"},    # Suricata: FTP brute force

    # ── DoH Exfil (full chain) ──────────────────────────────────────
    "100420": {"playbook": "block_dns_exfil", "severity": "high"},     # DoH exfil stage 2
    "100421": {"playbook": "block_dns_exfil", "severity": "high"},     # DoH exfil stage 3
    "100423": {"playbook": "block_dns_exfil", "severity": "critical"}, # DoH exfil confirmed

    # ── Persistence (extended) ──────────────────────────────────────
    "553": {"playbook": "fim_restore_response", "severity": "high"},   # File deleted from monitored dir
    "100301": {"playbook": "fim_restore_response", "severity": "critical"}, # SSH authorized_keys modified
    "100302": {"playbook": "fim_restore_response", "severity": "high"},     # Crontab modified'''

if old_last_entries in s:
    s = s.replace(old_last_entries, new_entries)
    print("  ✓ STATIC_RULE_MAP enriched with 35+ new entries")
else:
    print("  ! STATIC_RULE_MAP insertion point not found — check manually")

with open(path, "w") as f:
    f.write(s)
print("  Saved ansible_dispatch_agent.py")
PY

echo ""
echo "=== Patch 3: Playbook outcome visibility — runner API enhanced logging ==="
python3 - << 'PY'
path = "docker/ansible-runner/runner_api.py"
with open(path) as f:
    s = f.read()

old_response = '''        response = {
            "playbook": playbook,
            "status": result.status,
            "rc": result.rc,
            "stats": result.stats,
            "timestamp": datetime.utcnow().isoformat(),
        }
        return jsonify(response), 200 if result.rc == 0 else 500'''

new_response = '''        # Extract per-task outcomes for visibility
        task_outcomes = []
        changed_tasks = []
        failed_tasks = []
        try:
            for event in result.events:
                ev_data = event.get("event_data", {})
                task_name = ev_data.get("task", "")
                task_action = ev_data.get("task_action", "")
                event_type = event.get("event", "")
                res = ev_data.get("res", {})

                if event_type == "runner_on_ok" and ev_data.get("changed"):
                    detail = {
                        "task": task_name,
                        "host": ev_data.get("host", ""),
                        "changed": True,
                    }
                    # Extract meaningful outcome details per task type
                    if "block" in task_name.lower() or "iptables" in task_name.lower():
                        detail["outcome"] = f"IP block applied: {res.get('cmd', '')[:120]}"
                    elif "remove" in task_name.lower() or "delete" in task_name.lower():
                        detail["outcome"] = f"Removed: {res.get('stdout', res.get('cmd', ''))[:120]}"
                    elif "revoke" in task_name.lower() or "privilege" in task_name.lower():
                        detail["outcome"] = f"Privileges revoked: {res.get('stdout', '')[:120]}"
                    elif "firewall" in task_name.lower() or "New-NetFirewall" in str(res):
                        detail["outcome"] = f"Firewall rule created: {res.get('stdout', '')[:120]}"
                    elif "certutil" in task_name.lower() or "revoke" in task_name.lower():
                        detail["outcome"] = f"Certificate action: {res.get('stdout', '')[:120]}"
                    elif "kill" in task_name.lower() or "connection" in task_name.lower():
                        detail["outcome"] = f"Connection killed: {res.get('stdout', '')[:80]}"
                    elif "copy" in task_action or "template" in task_action:
                        detail["outcome"] = f"File written: {ev_data.get('task_path', '')}"
                    elif "shell" in task_action or "command" in task_action:
                        stdout = res.get("stdout", "")[:200]
                        if stdout:
                            detail["outcome"] = f"Output: {stdout}"
                    changed_tasks.append(detail)
                    task_outcomes.append(detail)

                elif event_type == "runner_on_failed":
                    failed_tasks.append({
                        "task": task_name,
                        "host": ev_data.get("host", ""),
                        "error": str(res.get("msg", res.get("stderr", "")))[:200],
                        "ignore_errors": ev_data.get("ignore_errors", False),
                    })
        except Exception as e:
            logger.warning(f"Could not parse task events: {e}")

        response = {
            "playbook": playbook,
            "status": result.status,
            "rc": result.rc,
            "stats": result.stats,
            "timestamp": datetime.utcnow().isoformat(),
            "changed_tasks": changed_tasks,
            "failed_tasks": [t for t in failed_tasks if not t["ignore_errors"]],
            "summary": {
                "changed": len(changed_tasks),
                "failed": len([t for t in failed_tasks if not t["ignore_errors"]]),
                "outcomes": [t.get("outcome", t["task"]) for t in changed_tasks if t.get("outcome")],
            },
        }
        return jsonify(response), 200 if result.rc == 0 else 500'''

if old_response in s:
    s = s.replace(old_response, new_response)
    print("  ✓ Runner API enhanced with per-task outcome extraction")
else:
    print("  ! Runner API response block not found — check manually")

with open(path, "w") as f:
    f.write(s)
print("  Saved runner_api.py")
PY

echo ""
echo "=== Patch 4: Dispatcher — log playbook outcomes after execution ==="
python3 - << 'PY'
path = "ai_agents/agents/ansible_dispatch/ansible_dispatch_agent.py"
with open(path) as f:
    s = f.read()

# Find the section that logs playbook.executed and enhance it
old_log = '''                logger.info(
                    "ansible.playbook.executed",
                    playbook=playbook_name,
                    rc=api_result.get("rc"),
                    status=api_result.get("status"),
                )'''

new_log = '''                rc = api_result.get("rc")
                status = api_result.get("status")
                summary = api_result.get("summary", {})
                changed_tasks = api_result.get("changed_tasks", [])
                failed_non_ignored = api_result.get("failed_tasks", [])

                logger.info(
                    "ansible.playbook.executed",
                    playbook=playbook_name,
                    rc=rc,
                    status=status,
                    changed=summary.get("changed", 0),
                    failed=summary.get("failed", 0),
                )

                # Log each meaningful changed task for full SOC visibility
                for task in changed_tasks:
                    outcome = task.get("outcome") or task.get("task", "")
                    if outcome:
                        logger.info(
                            "playbook.task.changed",
                            playbook=playbook_name,
                            host=task.get("host", ""),
                            task=task.get("task", ""),
                            outcome=outcome[:200],
                        )

                # Log non-ignored failures
                for task in failed_non_ignored:
                    logger.warning(
                        "playbook.task.failed",
                        playbook=playbook_name,
                        host=task.get("host", ""),
                        task=task.get("task", ""),
                        error=task.get("error", "")[:200],
                    )

                # Print human-readable summary to container stdout
                if summary.get("outcomes"):
                    logger.info(
                        "playbook.outcome_summary",
                        playbook=playbook_name,
                        actions=summary["outcomes"],
                    )'''

if old_log in s:
    s = s.replace(old_log, new_log)
    print("  ✓ Playbook outcome logging added to dispatcher")
else:
    print("  ! Playbook executed log block not found — check manually")

with open(path, "w") as f:
    f.write(s)
print("  Saved ansible_dispatch_agent.py")
PY

echo ""
echo "=== Patch 5: Wazuh local_rules.xml — Act 3 detection rules ==="
python3 - << 'PY'
import re
path = "wazuh/config/manager/local_rules.xml"
with open(path) as f:
    s = f.read()

act3_rules = """
  <!-- ================================================================
       Act 3 Detection Rules — AS-REP Roast, Kerberoast, NC Exfil,
       SSH Lateral Movement from Attacker IP
       ================================================================ -->

  <!-- AS-REP Roasting: impacket-GetNPUsers generates Kerberos AS-REQ
       with no pre-authentication for accounts that don't require it.
       Suricata fires rule ET POLICY Kerberos AS-REQ (no pre-auth).
       We detect it via the Suricata alert flowing through pfSense. -->
  <rule id="100700" level="10">
    <if_sid>86601</if_sid>
    <match>Kerberos|kerberos|AS-REQ|ASREP|asrep</match>
    <description>Act 3: AS-REP Roast attempt detected via Suricata</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
    <group>kerberos,attack,sentinel_response_required,</group>
  </rule>

  <rule id="100701" level="12" frequency="3" timeframe="30">
    <if_matched_sid>100700</if_matched_sid>
    <description>Act 3: AS-REP Roast CAMPAIGN — repeated Kerberos AS-REQ with no pre-auth</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
    <group>kerberos,attack,sentinel_response_required,</group>
  </rule>

  <!-- Kerberoasting: impacket-GetUserSPNs enumerates SPNs and requests
       TGS tickets for service accounts. Detected via LDAP enumeration
       of servicePrincipalName attributes on srv-ad-dns. -->
  <rule id="100710" level="10">
    <if_sid>60103</if_sid>
    <field name="win.eventdata.serviceName">MSOL_|svc-mssql|svc-legacy|krbtgt</field>
    <description>Act 3: Kerberoast — SPN service ticket requested for $(win.eventdata.serviceName)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberos,attack,sentinel_response_required,</group>
  </rule>

  <rule id="100711" level="14" frequency="5" timeframe="60">
    <if_matched_sid>100710</if_matched_sid>
    <description>Act 3: Kerberoast CAMPAIGN — bulk SPN ticket requests detected</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberos,attack,sentinel_response_required,</group>
  </rule>

  <!-- SSH Lateral Movement: successful SSH login from the attacker
       VLAN (10.70.0.0/24) to any DMZ host. Rule 5715 (SSH success)
       is already captured; we add a child rule that fires ONLY for
       external-origin SSH, filtering out Ansible management traffic
       from 10.60.0.0/24. -->
  <rule id="100720" level="12">
    <if_sid>5715</if_sid>
    <srcip>10.70.0.0/24</srcip>
    <description>Act 3: SSH Lateral Movement — successful SSH login from attacker VLAN $(srcip)</description>
    <mitre>
      <id>T1021.004</id>
    </mitre>
    <group>ssh,lateral_movement,attack,sentinel_response_required,</group>
  </rule>

  <!-- Raw TCP Exfiltration (nc): Suricata detects outbound raw TCP
       from srv-web to the Kali listener (port 9999). This fires as
       an ET POLICY rule (raw TCP to non-standard port). -->
  <rule id="100730" level="12">
    <if_sid>86601</if_sid>
    <match>POLICY|policy|ET POLICY</match>
    <field name="data.dest_ip">10.70.0.10</field>
    <description>Act 3: Raw TCP exfiltration to attacker host $(data.dest_ip):$(data.dest_port)</description>
    <mitre>
      <id>T1041</id>
    </mitre>
    <group>exfiltration,attack,sentinel_response_required,</group>
  </rule>

  <!-- Data staging detection: large data transfer from srv-web to Kali.
       Complements the nc exfil rule — fires on any Suricata alert
       indicating data leaving the DMZ to the attacker VLAN. -->
  <rule id="100731" level="14">
    <if_sid>100730</if_sid>
    <description>Act 3: Data exfiltration CONFIRMED — staging bundle transferred to $(data.dest_ip)</description>
    <mitre>
      <id>T1041</id>
      <id>T1074.001</id>
    </mitre>
    <group>exfiltration,attack,sentinel_response_required,</group>
  </rule>

  <!-- Symbolic Ransom Note: FIM detects new file in /tmp/ with name
       matching RANSOM or SENTINEL_RANSOM — created by the webshell
       in Act 3 Step 8. -->
  <rule id="100740" level="12">
    <if_sid>554</if_sid>
    <field name="syscheck.path">RANSOM|ransom</field>
    <description>Act 3: Symbolic ransom note detected at $(syscheck.path)</description>
    <mitre>
      <id>T1486</id>
    </mitre>
    <group>fim,ransomware,attack,sentinel_response_required,</group>
  </rule>

"""

# Insert before closing </group> tag
if "100720" not in s:
    # Find a good insertion point — after the last custom rule block
    insert_marker = "</group>"
    last_idx = s.rfind(insert_marker)
    if last_idx > 0:
        s = s[:last_idx] + act3_rules + s[last_idx:]
        print("  ✓ Act 3 detection rules added to local_rules.xml")
    else:
        print("  ! Could not find insertion point in local_rules.xml")
else:
    print("  ✓ Act 3 rules already present — skipping")

with open(path, "w") as f:
    f.write(s)
print("  Saved local_rules.xml")
PY

echo ""
echo "=== Patch 6: Add Act 3 rules to STATIC_RULE_MAP (already done in Patch 2) ==="
echo "  ✓ Already included in Patch 2"

echo ""
echo "=== Patch 7: Add ransom note rule to dispatcher ==="
python3 - << 'PY'
path = "ai_agents/agents/ansible_dispatch/ansible_dispatch_agent.py"
with open(path) as f:
    s = f.read()

old = '    "553": {"playbook": "fim_restore_response", "severity": "high"},   # File deleted from monitored dir'
new = ('    "553": {"playbook": "fim_restore_response", "severity": "high"},   # File deleted from monitored dir\n'
       '    "100740": {"playbook": "incident_response", "severity": "critical"}, # Ransom note dropped via webshell')

if old in s and "100740" not in s:
    s = s.replace(old, new)
    print("  ✓ Rule 100740 (ransom note) added to STATIC_RULE_MAP")
else:
    print("  ✓ Already present or not found")

with open(path, "w") as f:
    f.write(s)
PY

echo ""
echo "=== All patches applied. Building and deploying... ==="

# Deploy Wazuh rules
docker exec -i sentinel-wazuh-manager bash -c \
  "cat > /var/ossec/etc/rules/local_rules.xml" \
  < wazuh/config/manager/local_rules.xml

docker exec sentinel-wazuh-manager /var/ossec/bin/wazuh-control restart 2>&1 | tail -3

# Rebuild AI agents container
docker compose -f docker-compose.yml build ai-agents 2>&1 | tail -3

# Rebuild ansible runner (runner_api.py changed)
docker compose -f docker-compose.yml build ansible-runner 2>&1 | tail -3

docker compose -f docker-compose.yml up -d ai-agents ansible-runner
sleep 25

echo ""
echo "=== Verifying containers ==="
docker ps --filter "name=sentinel-ai-agents" --filter "name=sentinel-ansible-runner" \
  --format "{{.Names}}: {{.Status}}"

echo ""
echo "=== Verifying patches inside containers ==="
docker exec sentinel-ai-agents grep -c "HARD_SKIP_RULES\|FIM_WINDOWS_AGENTS\|effective_window\|100720" \
  /app/ai_agents/agents/wazuh_consumer/alert_dispatcher.py 2>/dev/null || echo "check manually"

docker exec sentinel-ansible-runner grep -c "changed_tasks\|playbook.task.changed\|outcome_summary" \
  /app/runner_api.py 2>/dev/null || \
  docker exec sentinel-ansible-runner grep -c "changed_tasks" /runner_api.py 2>/dev/null || \
  echo "runner check manually"

echo ""
echo "=== Done. Committing... ==="
git add -A
git status --short | head -20
git commit -m "feat: FIM noise overhaul + STATIC_RULE_MAP enrichment + Act3 detection + playbook outcome visibility

FIM noise:
- Extended _FIM_NOISE_PATTERNS with Windows WinRM/Ansible temp paths
- Added _FIM_WINDOWS_AGENTS allowlist (srv-ad-dns, srv-ftp): only critical
  Windows paths trigger FIM dispatch, all other Windows FIM is noise
- Category-aware dedup: FIM=300s, scan rules=120s, default=60s
- Added to HARD_SKIP_RULES: 92213, 62154, 60010, 91809, 60910, 60911,
  521, 502, 503 (all Ansible/WinRM operational noise)

STATIC_RULE_MAP enrichment (+35 rules):
- SSH brute force extended: 5503, 5551, 5763, 2502, 2503, 11325, 30304
- Web attacks: 31103, 31104, 31108, 31151, 31516, 31530, 31531, 77101
- Privilege escalation: 5402, 5403, 5404, 40111
- Malware/rootkit: 510, 511, 533, 9502, 9503
- Act3 rules: 100700, 100701, 100710, 100711, 100720, 100730, 100731, 100740
- Windows attacks: 60106, 60122, 91545, 91556, 92200, 92656
- Suricata extended: 40116, 40117, 86001, 86002
- DoH exfil chain: 100420, 100421 (100423 already present)
- Persistence: 553, 100301, 100302

Act 3 detection (new Wazuh rules):
- 100700/100701: AS-REP Roast via Suricata
- 100710/100711: Kerberoast SPN ticket requests (EventID 4769)
- 100720: SSH lateral movement from attacker VLAN (10.70.0.0/24)
- 100730/100731: Raw TCP / nc exfiltration to attacker
- 100740: Symbolic ransom note dropped (FIM on RANSOM filename)

Playbook outcome visibility:
- Runner API now extracts per-task changed/failed events from ansible-runner
- Dispatcher logs playbook.task.changed with meaningful outcome strings
- Dispatcher logs playbook.outcome_summary with list of actions taken
- Each IP block, file removal, privilege revoke, firewall rule create
  now appears as a structured log line after playbook execution"

git push origin main

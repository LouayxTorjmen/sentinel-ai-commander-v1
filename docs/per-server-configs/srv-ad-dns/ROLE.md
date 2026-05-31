# srv-ad-dns — Role-Specific Configuration

## Server role

**Primary function:** Domain Controller for the `mydomain.com` AD forest +
authoritative DNS server for the same domain. Hosts the Kerberos KDC,
LDAP/LDAPS endpoints, and AD object database.

**Service profile:**
- AD-DS / DNS (Windows Server 2019 Standard Evaluation)
- Forest/Domain: `mydomain.com`
- LDAP on 389, LDAPS on 636, GC on 3268, Kerberos on 88
- DNS on 53 (forwarder for `sentinel.lab` queries to srv-dns-bind)
- Pre-seeded service accounts: `svc-legacy/Summer2024!`, `svc-mssql/Welcome2024!`
- Sysmon installed (SwiftOnSecurity config)
- **Coming next:** Active Directory Certificate Services (AD-CS) for the
  ESC1-ESC8 cert abuse scenarios in Phase 2

**Wazuh agent:**
- ID: 081
- Name: WinServer2019-agent
- Hostname: srv-ad-dns (computer hostname)

## Current state analysis

The existing ossec.conf is **already well-customized** — extensive registry
monitoring, PowerShell channels, Sysmon, TaskScheduler, TerminalServices. This
config does NOT need a full rebuild. Targeted changes only.

### Issues to fix

| Issue | Action |
|---|---|
| FIM on every `C:\Users\*\Desktop/Downloads/...` | DC has only Administrator. Scope to that user only. |
| `C:\Program Files\Suricata\log\eve.json` localfile (Suricata not installed here) | Drop or comment out |
| Sysmon localfile present once but config has trailing duplicate-comment area | Verify, dedupe if found |
| Vulnerability detector firing on fake CVE-2026-xxxxx | Out-of-band — Wazuh's vuln-detector module has stale state, not in ossec.conf scope |

### Top noise sources (from rule.id query)

| Rule | Count | Why it's noise |
|---|---|---|
| 60106 Windows Logon Success | Very high | Every login, including service account auth, DC computer account login |
| 60137 Windows User Logoff | High | Counterpart to 60106 |
| 92052 Suspicious Windows cmd shell execution | Medium | Wazuh's heuristic fires on every elevated cmd run from PowerShell |
| 92032 Suspicious Windows cmd shell execution | Medium | Same family |
| 92201 PowerShell created scripting file under Temp | Medium | Routine for PowerShell ops on a DC |
| 92021 PowerShell delete files | Medium | Routine admin operations |
| 92307 Service creation evidence | Low-medium | Wazuh installer's own service registrations |
| 62154 Defender platform config changed | Low | Routine Defender update |

The noisy ones (60106, 60137, 92052, 92032, 92201, 92021) all need to be either
**downgraded to level 0** (silently routed) for routine cases, or **scoped tighter**
to only fire when context is genuinely suspicious.

### AD-specific signal we're MISSING

Currently NOT monitored but should be:

| Event | Why valuable |
|---|---|
| 4625 (Failed logon) | Already covered by Wazuh rule 60122 but not parented to a brute-force escalation |
| 4768/4769 Kerberos ticket events | Golden/Silver Ticket detection (T1558) |
| 4624 with Logon Type 9 (NewCredentials) | RunAs / pass-the-hash indicator |
| 4738 (User account changed) | Account manipulation |
| 4720/4722/4724 (User added / enabled / password reset) | Account creation/manipulation |
| 5379 (Credential Manager access) | Credential dumping |
| AD Object Audit | Requires audit policy enabled — we'll note it but not configure |

## Custom service-specific manager rules

| Rule ID | Trigger | Description |
|---|---|---|
| 100200 | Wazuh rule 60122 (4625 failed logon) burst 8+ in 120s, same source | AD/Kerberos brute force |
| 100201 | Event 4624 with LogonType=9 | NewCredentials logon — possible PTH/PassTheHash indicator |
| 100202 | Event 4720 (user created) outside business hours (UTC 22:00-06:00) | Suspicious account creation timing |
| 100203 | Event 4768 with pre-auth failure (Kerberos) burst | AS-REP roasting attempt |
| 100204 | Service install (event 7045) where service binary path is NOT `C:\Windows\System32\*` | Non-standard service install (T1543) |
| 100205 | Sysmon EventID 1 process_name=mimikatz (or known dump tool) | Direct credential dump attempt |

(Rules for AD-CS abuse — ESC1-ESC8 — added in Phase 2 when AD-CS is installed.)

## Noise to suppress (this agent)

| Wazuh rule | Action | Why |
|---|---|---|
| 60106 (Logon Success) | Level 0 for this agent | DC has constant service account / computer account auth |
| 60137 (User Logoff) | Level 0 for this agent | Counterpart noise |
| 92052/92032 (Suspicious cmd) | Level 0 for this agent | Heuristic prone to FP on a DC |
| 92201 (PowerShell creates script file) | Level 3 (downgrade from level 7) for this agent | Routine for DC PowerShell |
| 92021 (PowerShell deletes files) | Level 3 (downgrade from level 7) | Routine admin work |

Note: When the AD-CS install starts (Phase 2), these may temporarily fire from
the installer process. The downgrades hide the routine cases while keeping
the events for post-hoc forensic review (level 0 still logs, just doesn't alert).

## Volume estimate

Before tuning (idle, last 1h): ~80-100 alerts/hour from this host.
After tuning (idle): ~10-15 alerts/hour.
During scenario run (Kerberoasting + AS-REP roasting + ticket request): ~50-80
alerts depending on actor.

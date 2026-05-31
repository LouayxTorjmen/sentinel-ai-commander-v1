# srv-ftp — Role-Specific Configuration

## Server role

**Primary function:** IIS FTP server hosting deliberately-weak credentials
(matching the seeded `infra_credentials` in MySQL). Acts as the secondary
post-exploit target after web/SQL compromise.

**Service profile:**
- Windows 10 Pro (workstation-class OS hosting IIS FTP for the lab)
- IIS FTP service (port 21)
- FTP root: `C:\inetpub\ftproot\`
- Pre-seeded FTP users (matching credential DB): `svc-legacy`, `transfer`, etc.
- Sysmon installed (SwiftOnSecurity config)
- **Coming next:** IIS HTTP with deliberately-weak TLS cert (testssl.sh target)

**Wazuh agent:**
- ID: 085
- Name: srv-ftp (matches hostname)
- Hostname: srv-ftp

## Current state issues

The existing ossec.conf is **mostly Wazuh default** with two minor additions:

| Issue | Impact |
|---|---|
| Default FIM `recursion_level="0"` on Windows dirs | Only top-level files checked — useless for catching dropped tools in subdirs |
| FIM `restrict="..."` on `regedit.exe|cmd.exe|...` | Only watches replacement of specific binaries; ignores everything else |
| `C:\Users\Louay-Windows\Desktop` is the only per-user FIM | This is a real interactive user; OK but should be broader |
| Default Security event query filters too aggressively | Drops EventID 5145 (file share access) — but we want to see SMB activity to /inetpub/ftproot |
| NO IIS FTP log collection | **Primary signal source missing**. IIS logs aren't being read at all. |
| NO IIS HTTP log collection (Phase 2 pending) | Will need adding |
| Default Wazuh recursion=0 on `%WINDIR%` | Misses subdir intrusions |
| Excessive registry monitoring at HKEY_LOCAL_MACHINE\Security | Generates noise from routine LSA updates |
| Sysmon localfile present but in wrong position | Fine as-is, no issue |
| SCA "Integration checksum failed" repeating in log | Wazuh manager bug with cis_win10_enterprise.yml — disable SCA temporarily |

### Top noise sources (current)

| Rule | Description | Action |
|---|---|---|
| 92910 | OneDrive accessing Explorer process | Suppress |
| 92200 | Scripting file under Temp | Downgrade |
| 23502 | CVE vulnerability fixed | Out of scope (vuln-detector module issue) |
| 92154 | Process loaded taskschd.dll | Suppress (FP on routine boot) |
| 92307 | New service registration (BluetoothUserService) | Suppress per-user service patterns |
| 92021 | PowerShell delete files | Downgrade |
| 92205 | PowerShell created exe in root | Suppress (FP - DLL loader behavior) |
| 92031 | Discovery activity | Suppress (Defender benign scans) |
| 92110 | WinRM activity localhost-to-localhost | Suppress (FP — IPv6 loopback) |
| 60132 | System time changed | Downgrade (NTP routine sync) |
| 60642 | Software protection service | Suppress |
| 19009 | CIS benchmark fail | Drop ALL CIS findings noise (downgrade to 0) |

## What this bundle adds

### Major FIM rebuild
The default Wazuh FIM with `recursion_level="0"` is essentially useless for
catching real attacks. We replace it with:

- Top-level + recursion 2 on `C:\inetpub\` (catches dropped webshells, FTP uploads)
- Real-time + report_changes on `C:\inetpub\wwwroot\` (IIS HTTP doc root, Phase 2 target)
- Real-time + report_changes on `C:\inetpub\ftproot\` (FTP upload target)
- Real-time on `C:\Windows\System32\inetsrv\config\` (IIS config)
- Real-time on `C:\Windows\System32\inetsrv\` (IIS binaries)
- Real-time on `C:\inetpub\logs\LogFiles\` (IIS log dir — detect log clearing)
- Real-time on `C:\Users\Louay-Windows\Desktop/Documents/Downloads`
- Real-time on `C:\Users\Public`
- Standard startup paths, scheduled tasks, etc.

### NEW localfile sources
- IIS FTP log: `C:\inetpub\logs\LogFiles\FTPSVC*\u_ex*.log` (currently MISSING)
- IIS HTTP log: `C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log` (Phase 2 prep)
- All the same Windows event channels srv-ad-dns has (PowerShell, TaskScheduler,
  TerminalServices, Sysmon, Defender)
- Microsoft-Windows-IIS-Logging/Logs channel

### SCA tuning
- Disable `scan_on_start` for SCA (stops the checksum-failed retry loop)
- Increase SCA interval from 12h to 24h

## Custom service-specific manager rules

| Rule ID | Trigger | Description |
|---|---|---|
| 100230 | IIS FTP log: failed login attempts burst (5+ in 60s) | FTP brute force |
| 100231 | FIM file added under `C:\inetpub\wwwroot\` with `.aspx`/`.php`/`.jsp` ext | **HTTP webshell drop** |
| 100232 | FIM file added under `C:\inetpub\ftproot\` with executable ext | FTP suspicious upload |
| 100233 | Sysmon EID 11 (file create) under `C:\inetpub\` by non-w3wp/non-ftp process | Lateral drop |
| 100234 | IIS service stopped (event 7036) | **Possible defense evasion** |
| 100235 | Real-time FIM on `C:\Windows\System32\inetsrv\config\applicationHost.config` | IIS config tamper |

## Noise to suppress for this agent

| Rule | Action | Why |
|---|---|---|
| 92910 (OneDrive accessing Explorer) | Level 0 | Routine OneDrive update process |
| 92154 (taskschd.dll loaded) | Level 0 | Loaded by many normal processes |
| 92307 (BluetoothUserService_NNN created) | Level 0 with match pattern | Per-user system service noise |
| 92205 (PowerShell exe in Windows root) | Level 3 | Routine for installers |
| 92031 (Discovery activity) | Level 3 | Defender benign scans |
| 92110 (WinRM loopback) | Level 0 | Loopback-to-loopback is benign |
| 60132 (System time changed) | Level 3 | NTP sync |
| 60642 (Software protection service) | Level 0 | Activation routine |
| 19009 (CIS benchmark - 'Password history') | Level 0 | One-time install state |

## Volume estimate

Before tuning (idle): ~60-80 alerts/hour
After tuning (idle): ~10-15 alerts/hour
During FTP brute force attack: ~30-50 alerts (rule 100230 + 60122 chain)
During webshell drop scenario: ~10-20 alerts including high-severity 100231

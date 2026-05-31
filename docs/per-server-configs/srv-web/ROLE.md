# srv-web — Role-Specific Configuration

## Server role

**Primary function:** PHP web application server hosting DVWA (Damn Vulnerable
Web Application) backed by MySQL on srv-sql. Acts as the primary HTTP attack
surface for the scenario orchestrator's Initial Access phase (T1190 + T1078).

**Service profile:**
- Apache 2.4.58 on port 80, serving DVWA at `/dvwa/`
- MySQL client connections outbound to srv-sql (10.50.0.13)
- DVWA `infra_credentials` table seeded with 7 rows (5 real + 2 decoy)
- Webshell drop target: `/var/www/html/dvwa/hackable/uploads/sentinel_shell.php`
- **Coming next**: nginx with deliberately-weak TLS cert (for encrypted-attack scenario)
- No FTP, no mail, no DNS, no AD

**Wazuh agent:**
- ID: 089
- Name: Ubuntu-agent-web
- Hostname: srv-web

## Current state issues

Analyzing the existing ossec.conf revealed three malformed-config issues:

1. **TWO `<ossec_config>` blocks.** A second block exists after the first
   one closes. Wazuh's parser reads only the first; the second is silently
   ignored. The orphaned block has localfile entries for `vsftpd.log`,
   `dpkg.log`, journald, and a duplicate falco.json — none of which are
   actually being collected.

2. **Apache logs are NOT being read.** `/var/log/apache2/access.log` and
   `/var/log/apache2/error.log` have no `<localfile>` entry. This is the
   primary attack surface and we have ZERO HTTP-level visibility.

3. **vsftpd.log is referenced but there is no vsftpd on srv-web.** The FTP
   server is on srv-ftp (10.50.0.14, Windows). Dead config.

## What is signal, what is noise

### High-value telemetry (keep + add)

| Source | Why it matters |
|---|---|
| `/var/log/apache2/access.log` | **Currently missing**. SQL injection patterns, webshell access (`?cmd=`), credential brute force on `/dvwa/login.php` |
| `/var/log/apache2/error.log` | **Currently missing**. PHP errors, mod_security alerts (if enabled), reverse-shell php attempts |
| `/var/log/auth.log` | **Currently missing**. SSH brute force (rules 5712, 5716), sudo escalation |
| `/var/log/syslog` | systemd, kernel, AppArmor denials |
| `/var/log/falco/falco.json` | eBPF syscalls — webshell-spawned bash, reverse shells, sensitive file reads |
| `/var/log/suricata/eve.json` | Network-side IDS (if forwarding here) |
| FIM real-time on `/var/www/html/dvwa/` | **Webshell drop detection** (this is the attack target!) |
| FIM real-time on `/etc/apache2/` | Web server config tampering |
| FIM real-time on `/etc/nginx/` | (coming) — nginx config tampering |
| FIM real-time on `/etc/ssl/private/` | Private key access/modification |
| FIM real-time on `/etc/ssl/certs/` | Cert tampering / fabrication scenarios |

### Low-value telemetry (drop)

| Source | Why noise |
|---|---|
| `/var/log/vsftpd.log` | No vsftpd installed |
| `/var/log/dpkg.log` | No internet, no packages installed |
| `<wodle name="osquery">` | Osquery isn't installed; disabled |
| `<wodle name="cis-cat">` | Not licensed; disabled |
| FIM real-time on `/home` | No real users — service-only box |
| FIM `/usr/bin /usr/sbin /bin /sbin` real-time | Redundant with Falco eBPF |
| Pre-built netstat / last commands at 6m | Excessive on stable host |
| 1h syscollector interval | Reduce to 30m (still polled regularly) |

### Tuning summary

| Change | Rationale |
|---|---|
| **Merge two ossec_config blocks** | Bug fix — make all localfile entries actually load |
| Add Apache localfiles | Currently missing primary log source |
| Add auth.log + syslog localfiles | Currently missing OS-level audit |
| Real-time FIM on `/var/www/html/dvwa/` | Specific attack target |
| Real-time FIM on `/etc/apache2/`, `/etc/nginx/`, `/etc/ssl/` | Config + cert tampering |
| Drop vsftpd.log, dpkg.log | Dead/irrelevant |
| Disable empty wodles (osquery, cis-cat) | Already disabled, clean up file |
| Drop netstat/last commands | Covered by syscollector |

## Custom service-specific manager rules

| Rule ID | Trigger | Description |
|---|---|---|
| 100150 | FIM change on `/var/www/html/dvwa/hackable/uploads/*.php` | **Webshell drop detected** (T1505.003) |
| 100151 | FIM change on `/etc/apache2/*.conf` | Apache config tampering |
| 100152 | FIM change on `/etc/nginx/*.conf` | nginx config tampering |
| 100153 | FIM change on `/etc/ssl/private/*` | TLS private key modified |
| 100154 | Apache 500 errors burst (5+ in 60s from same source) | Possible SQLi probing / fuzzing |
| 100155 | Falco: `apache2` or `nginx` process spawning shell-like child | Webshell exec |
| 100156 | Falco: `apache2` process reading sensitive file | LFI exploit |

## Cross-source correlation rules

| Rule ID | Trigger | Description |
|---|---|---|
| 100170 | Rule 100150 (webshell drop) + Suricata HTTP request to that path within 60s | **High-confidence webshell delivery** — drop detected + access detected |
| 100171 | Falco shell spawn by apache2 + outbound network connection within 30s | Reverse shell exfil from compromised web server |

## Noise to suppress

| Wazuh rule | Action | Reason |
|---|---|---|
| 5501 (PAM session opened) | Suppress for this agent | Routine SSH-in for admin work |
| 5502 (PAM session closed) | Suppress for this agent | Routine SSH-out |
| 5402 (Successful sudo) | Keep but level 0 for this agent | Routine admin sudo from your shell |

## Volume estimate

Before tuning (idle): ~30 alerts/hour (PAM noise, FIM dpkg-equivalent churn,
syscollector deltas).
After tuning (idle): ~3-5 alerts/hour.
During scenario run: ~120 alerts (webshell drop, SQLi pattern matches, Falco
syscall events from PHP-spawned processes, Apache 500 bursts).

## Also fixed: rule 100131 false positive

Rule 100131 from the srv-dns-bind bundle was firing falsely because its
`frequency=2` clause was satisfied by just two routine sudo events. Tightened
to require BOTH rule 100121 (zone file modified) AND rule 5402 (sudo), each
appearing exactly once in the timeframe — not "any two of these sids".

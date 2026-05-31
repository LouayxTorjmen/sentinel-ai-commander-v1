# srv-dns-bind — Role-Specific Configuration

## Server role

**Primary function:** Authoritative + recursive DNS resolver for the `sentinel.lab` zone,
serving as the secondary nameserver alongside the AD-integrated DNS on srv-ad-dns.

**Service profile:**
- BIND 9.18 listening on TCP/UDP 53
- Optional DoH endpoint on TCP 443 (`/dns-query`) when DoH addition is deployed
- Hosts the deliberately-disclosed `sentinel.lab` zone (17 records, used by the
  attack scenario for AXFR-based recon)
- No web, no database, no mail, no file shares

**Wazuh agent ID:** 014

## What is signal, what is noise

### High-value telemetry (keep)

| Source | Why it matters |
|---|---|
| `/var/log/bind/query.log` | Every DNS query — recon detection (AXFR, SRV enumeration, kerberos lookups) |
| `/var/log/auth.log` | SSH brute force, sudo escalation attempts |
| `/var/log/falco/falco.json` | eBPF syscall events — process spawning by named, file access by attacker shells |
| `/var/log/suricata/eve.json` | Network-side IDS alerts forwarded from the pfSense Suricata instance |
| FIM real-time on `/etc/bind/` | BIND config or zone-file tampering |
| FIM real-time on `/var/named/` | Zone-data integrity (if present) |
| FIM on `/root/.ssh/`, `/home/*/.ssh/` | Backdoor key implantation |

### Low-value telemetry (drop or downgrade)

| Source | Why it's noise here |
|---|---|
| `/var/log/apache2/access.log` and `error.log` | **There is no Apache on this host.** Leftover from generic template. |
| FIM on `/var/www/, /srv/` | No web content on this server. |
| FIM real-time on `/usr/bin, /usr/sbin, /bin, /sbin` | **Redundant with Falco's syscall-level eBPF coverage.** Falco catches every `execve` from these paths in real-time; periodic checksum comparison adds nothing. Downgrade to 24h scheduled scan for binary-replacement detection. |
| Rule 5501/5502 PAM session open/close | Every sudo, every SSH login fires both rules. Routine admin activity. **Suppress at manager level for this agent.** |
| Rule 5402 "Successful sudo to ROOT" | Same as above — pure admin noise. Suppress except when source IP is outside the management VLAN. |
| Daily Wazuh syscollector at 1-minute intervals | Overkill on a stable single-purpose box. Lower to 30 minutes. |
| `dpkg.log` | No internet access — packages aren't being installed. Drop. |

### Adjustments and additions

| Change | Rationale |
|---|---|
| Drop syscheck on `/usr/bin /usr/sbin /bin /sbin` real-time | Covered by Falco eBPF. Keep ONE 24h scheduled scan to catch binary swaps. |
| Add real-time FIM on `/etc/bind/`, `/etc/named.conf*` | Critical config — any change is suspicious |
| Add real-time FIM on `/etc/falco/` | Falco config tampering = attacker disabling detection |
| Drop Apache localfiles | Dead branch |
| Drop `/srv` and `/var/www` from syscheck | Not used on this host |
| Lower syscollector frequency from 1m to 30m | Reduce indexer load on a stable host |
| Add `<localfile>` for `/var/log/named/named.log` | BIND service-level errors (not just queries) |

## Custom service-specific manager rules

Beyond the existing rules 100100-100103 (DNS query base + flood + AXFR + SRV
enum), this role gets:

| Rule ID | Trigger | Description |
|---|---|---|
| 100120 | FIM change on `/etc/bind/*.conf` | BIND config tampered with |
| 100121 | FIM change on `/etc/named.conf` or zone files | DNS authority data modified |
| 100122 | Falco `proc.name=named` writing to `/var/named/` or `/etc/bind/` outside startup | Named compromise indicator |
| 100123 | DNS query for known DGA-like patterns (high-entropy subdomains) | DGA C2 indicator |
| 100124 | DoH endpoint (`/dns-query`) accessed from non-allowlisted source | DoH abuse detection |

## Cross-source correlation rules

These fire only when multiple telemetry layers agree:

| Rule ID | Trigger | Description |
|---|---|---|
| 100130 | Rule 100100 (DNS query) + Rule 86601 (Suricata applayer mismatch) within 30 seconds, same srcip | DNS recon w/ malformed traffic — likely automated tool fingerprinting |
| 100131 | Rule 100121 (BIND zone change via FIM) + Rule 5402 (sudo to root) within 5 min, different users | Zone tampered by unexpected admin |

## Noise to suppress at the manager (this agent only)

| Wazuh rule | Action | Why |
|---|---|---|
| 5501 (PAM session opened) | Lower level from 3 to 0 if agent.id=014 | Pure noise |
| 5502 (PAM session closed) | Lower level from 3 to 0 if agent.id=014 | Pure noise |
| 5402 (Successful sudo) | Keep but elevate to level 6 only if srcip outside 10.99.0.0/24 (MGMT VLAN) | Only suspicious if from non-mgmt |

## Volume estimate

Before tuning: ~40 alerts/hour from this host during idle (PAM, sudo, FIM dpkg-like churn).
After tuning: ~3-5 alerts/hour during idle, all from genuinely interesting events.
During scenario run: ~70 alerts (DNS recon, FIM webshell, Falco syscall events).

The tuning **reduces idle noise by ~90%** while preserving 100% of scenario-relevant signal.

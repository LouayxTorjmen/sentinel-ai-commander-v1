# srv-sql — Role-Specific Configuration

## Server role

**Primary function:** MySQL 8.4 database server backing DVWA's `infra_credentials`
and `sentinel_lab` tables. Receives queries exclusively from srv-web (10.50.0.12).

**Service profile:**
- MySQL 8.4 listening on TCP 3306 (bound to 10.50.0.13 from DMZ)
- 7 seeded credentials (5 real + 2 decoys) in `infra_credentials`
- Root password: `louay` (deliberately weak for scenario)
- Three application users: `dvwa`, `sentinel_app`, `sentinel_ro`
- **Coming next**: MySQL Enterprise audit plugin (or `audit_log` plugin) for
  query-level logging
- No web, no DNS, no AD, no FTP

**Wazuh agent:**
- ID: 015
- Name: auto-victim2-rhel
- Hostname: srv-sql

## Current state issues

| Issue | Impact |
|---|---|
| Apache localfiles (`/var/log/httpd/access_log`) configured | No Apache on this host — dead config |
| FIM real-time on `/var/www`, `/srv` | No web content — dead config |
| `dpkg.log` not relevant (RHEL uses yum/dnf) | N/A on this distro anyway |
| MySQL log `/var/log/mysql/mysqld.log` NOT being collected | **Primary signal source missing** |
| `/var/lib/mysql/` not under FIM | DB binlog/data tampering invisible |
| Syscollector at 1m interval | Stable DB host — overkill |
| Pre-built netstat command at 6m | Covered by syscollector |

## What is signal, what is noise

### High-value telemetry (keep + add)

| Source | Why it matters |
|---|---|
| `/var/log/mysql/mysqld.log` | **Currently missing**. Connection failures, privilege violations, plugin issues |
| `/var/log/audit/audit.log` | Linux auditd — privilege escalation, kernel events |
| `/var/log/secure` | RHEL's auth log equivalent — SSH, sudo, su |
| `/var/log/messages` | systemd, kernel, hardware |
| `/var/log/falco/falco.json` | eBPF — mysqld spawning unexpected children, sensitive file access by mysqld |
| FIM real-time on `/etc/my.cnf*` and `/etc/my.cnf.d/` | MySQL config tampering |
| FIM real-time on `/var/lib/mysql/*.cnf` | per-DB configuration files |
| FIM real-time on `/etc/falco/` | Detection-tool tampering |

### Low-value telemetry (drop)

| Source | Why noise |
|---|---|
| `/var/log/httpd/*` | No httpd installed |
| FIM real-time on `/var/www`, `/srv` | No web content |
| `<wodle name="cis-cat">` | Not licensed; disabled anyway |
| FIM real-time on `/home` | No interactive users |
| Pre-built netstat at 6m | Covered by syscollector |
| Pre-built last at 6m | Covered by syscollector + auth.log |

### Falco false-positive: packagekitd

Same pattern as we saw with wazuh-syscheckd on the Ubuntu hosts. On RHEL,
PackageKit polls package state and reads PAM config (`/etc/pam.d/*`), firing
Falco rule 100114 (Read sensitive file). Add `packagekitd` to the Falco
exemption list.

## Custom service-specific manager rules

| Rule ID | Trigger | Description |
|---|---|---|
| 100180 | FIM change on `/etc/my.cnf*` or `/etc/my.cnf.d/*` | MySQL config tampered |
| 100181 | FIM change on `/var/lib/mysql/*.cnf` | Per-DB config tampered |
| 100182 | MySQL error log: "Access denied for user" — burst (5+ in 60s) | Brute force / credential probe |
| 100183 | Falco: `mysqld` process spawning shell-like child | Possible SQL exec into RCE |
| 100184 | Falco: `mysqld` reading sensitive file outside its data dir | mysqld exploitation |

## Cross-source correlation rules

| Rule ID | Trigger | Description |
|---|---|---|
| 100185 | Rule 100182 (auth fail burst) + Suricata MySQL detection from same srcip within 60s | Coordinated DB brute force |
| 100186 | Rule 100183 (mysqld shell) + outbound network within 30s | mysqld → RCE → exfil chain |

## Noise to suppress (this agent)

| Rule | Action | Why |
|---|---|---|
| 5501 / 5502 (PAM sessions) | Level 0 for hostname=auto-victim2-rhel | Routine |
| 5402 (sudo to root) | Level 0 for this agent | Routine admin |

## Falco-side fix (packagekitd exemption)

Updated `/etc/falco/falco_rules.local.yaml` adds `packagekitd` to the
exempt processes list, same pattern as we did for wazuh-syscheckd.

## Volume estimate

Before tuning: ~30 alerts/hour idle (PAM noise, Falco packagekitd, FIM churn)
After tuning: ~3 alerts/hour idle
During scenario: ~40 alerts (MySQL brute force, FIM on staged data files,
Falco syscall events from sql injection-spawned processes)

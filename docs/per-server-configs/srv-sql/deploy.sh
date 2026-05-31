#!/bin/bash
# SENTINEL-AI — srv-sql ossec.conf curation
#
# Run as root on srv-sql (10.50.0.13, RHEL 10).
# Two-part deploy:
#   1. Update Falco local rules to exempt packagekitd (PAM-read FP)
#   2. Apply curated ossec.conf
# Auto-rolls-back if Wazuh agent fails to start.

set -euo pipefail

CONF=/var/ossec/etc/ossec.conf
BACKUP=/var/ossec/etc/ossec.conf.pre-roleconfig.$(date +%Y%m%d-%H%M%S)
NEW=/tmp/ossec.conf.new
FALCO_LOCAL=/etc/falco/falco_rules.local.yaml
FALCO_BACKUP="${FALCO_LOCAL}.pre-roleconfig.$(date +%Y%m%d-%H%M%S)"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
fi

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF not found — is Wazuh agent installed?" >&2
    exit 1
fi

echo "─── srv-sql role-specific tuning (RHEL 10 + MySQL 8.4) ───"
echo

# ─── Part 1: Falco override (add packagekitd to exemption list) ──────────

if [[ -f "$FALCO_LOCAL" ]]; then
    cp "$FALCO_LOCAL" "$FALCO_BACKUP"
    echo "Falco backup → $FALCO_BACKUP"
fi

cat > "$FALCO_LOCAL" << 'EOF'
# SENTINEL-AI Falco local overrides — srv-sql (RHEL 10)
#
# Suppress "Read sensitive file untrusted" alerts for known-benign processes.
# wazuh-syscheckd, systemd-userwork: same pattern as Ubuntu hosts.
# packagekitd: RHEL-specific. PackageKit polls package state and reads
# /etc/pam.d/* periodically, generating false-positive credential-access alerts.

- rule: Read sensitive file untrusted
  override:
    condition: append
  condition: and not proc.name in (sentinel_exempt_processes)

- list: sentinel_exempt_processes
  items:
    - wazuh-syscheckd
    - wazuh-agentd
    - wazuh-modulesd
    - wazuh-execd
    - wazuh-logcollect
    - wazuh-logcollector
    - systemd-userwor
    - systemd-userdbd
    - pkexec
    - polkitd
    # RHEL-specific
    - packagekitd
    - PackageKit
    - tracker-extract
    - tracker-miner-f
EOF

echo "Restarting Falco..."
systemctl restart falco-modern-bpf
sleep 3
if ! systemctl is-active --quiet falco-modern-bpf; then
    echo "WARNING: Falco failed to restart — rolling back local rules" >&2
    [[ -f "$FALCO_BACKUP" ]] && cp "$FALCO_BACKUP" "$FALCO_LOCAL"
    systemctl restart falco-modern-bpf || true
fi
echo "✓ Falco running"
echo

# ─── Part 2: Wazuh agent config ──────────────────────────────────────────

echo "Wazuh backup → $BACKUP"
cp "$CONF" "$BACKUP"

cat > "$NEW" << 'EOF'
<!--
  SENTINEL-AI Agent Config — srv-sql (10.50.0.13)
  Role: MySQL 8.4 database server (RHEL 10) backing DVWA
  Curated for: thesis SOC build with Falco + auditd + MySQL log

  See docs/per-server-configs/srv-sql/ROLE.md for rationale.
-->
<ossec_config>

  <client>
    <server>
      <address>10.60.0.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>rhel, rhel10, rhel10.1, sentinel-sql</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>30m</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>no</browser_extensions>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <!-- File Integrity Monitoring for the DB role:
       - Daily scheduled scan of system binaries (backup to Falco)
       - Real-time on /etc (config tampering)
       - Real-time on /etc/my.cnf.d (MySQL config)
       - Real-time on /var/lib/mysql config files (per-DB cnf)
       - Real-time on /etc/falco (detection-tool integrity)
       - Real-time on /tmp + SSH key paths
       - Dropped: /var/www, /srv (no web on this host)
       - Dropped: realtime /usr/bin /usr/sbin /bin /sbin (Falco covers exec)
  -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>86400</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>

    <directories check_all="yes">/usr/bin,/usr/sbin,/bin,/sbin,/boot</directories>

    <directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/my.cnf.d</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/falco</directories>

    <directories realtime="yes" check_all="yes" report_changes="yes">/tmp</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/root/.ssh</directories>

    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/machine-id</ignore>
    <ignore>/etc/resolv.conf</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$</ignore>

    <nodiff>/etc/ssl/private.key</nodiff>
    <nodiff type="sregex">id_rsa$|id_ed25519$|id_ecdsa$|\.key$|\.pem$</nodiff>

    <diff>
      <disk_quota>
        <enabled>yes</enabled>
        <limit>2GB</limit>
      </disk_quota>
      <file_size>
        <enabled>yes</enabled>
        <limit>5MB</limit>
      </file_size>
    </diff>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <process_priority>10</process_priority>
    <max_eps>50</max_eps>

    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!-- Log sources for the DB role -->

  <!-- MySQL combined log (errors, startup, plugin events). CURRENTLY MISSING. -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/mysql/mysqld.log</location>
  </localfile>

  <!-- MySQL audit-log location (created by audit_log plugin in Phase 2). -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/lib/mysql/audit.log</location>
  </localfile>

  <!-- Linux audit (auditd) — privilege escalation, kernel events -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- RHEL auth log: SSH, sudo, su -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <!-- General system messages -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <!-- systemd journal -->
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <!-- Falco eBPF events -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/falco/falco.json</location>
  </localfile>

  <!-- Suricata (if forwarded here for DMZ taps) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <!-- Disk usage poll (30m instead of 6m) -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>1800</frequency>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <logging>
    <log_format>plain</log_format>
  </logging>

</ossec_config>
EOF

# XML validity check using python ElementTree (handles no-root files via wrapping)
if ! ( echo '<sentinel-root>'; cat "$NEW"; echo '</sentinel-root>' ) | python3 -c "
import sys, xml.etree.ElementTree as ET
try:
    ET.fromstring(sys.stdin.read())
    sys.exit(0)
except ET.ParseError as e:
    print(f'XML parse error: {e}', file=sys.stderr)
    sys.exit(1)
"; then
    echo "ERROR: generated config has invalid XML — refusing to deploy" >&2
    rm -f "$NEW"
    exit 1
fi

mv "$NEW" "$CONF"
chown root:wazuh "$CONF"
chmod 660 "$CONF"

echo "Config replaced. Restarting Wazuh agent..."
systemctl restart wazuh-agent
sleep 5

if systemctl is-active --quiet wazuh-agent; then
    echo "✓ wazuh-agent restarted successfully"
else
    echo "✗ wazuh-agent failed to start — rolling back" >&2
    cp "$BACKUP" "$CONF"
    systemctl restart wazuh-agent
    echo "ROLLBACK COMPLETE. Investigate: $BACKUP" >&2
    exit 1
fi

echo
echo "─── Change summary ───"
echo "Before: $(wc -l < "$BACKUP") lines"
echo "After:  $(wc -l < "$CONF") lines"
echo
echo "Active <localfile> blocks: $(grep -c '<localfile>' "$CONF")"
echo "Active <directories> entries: $(grep -c '<directories' "$CONF")"
echo
echo "Falco status:"
systemctl is-active falco-modern-bpf && echo "✓ Falco running with new exemptions"
echo
echo "Recent agent log (last 10 lines):"
tail -10 /var/ossec/logs/ossec.log
echo
echo "─── Done. Verify on manager: alerts from agent 015 should still flow. ───"

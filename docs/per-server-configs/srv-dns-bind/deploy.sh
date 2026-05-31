#!/bin/bash
# SENTINEL-AI — srv-dns-bind ossec.conf curation
#
# Run as root on srv-dns-bind (10.50.0.11).
# Backs up the current config, applies the role-specific tuning,
# verifies the agent restarts cleanly, and prints a summary.
#
# See ROLE.md for rationale of each change.

set -euo pipefail

CONF=/var/ossec/etc/ossec.conf
BACKUP=/var/ossec/etc/ossec.conf.pre-roleconfig.$(date +%Y%m%d-%H%M%S)
NEW=/tmp/ossec.conf.new

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root" >&2
    exit 1
fi

if [[ ! -f "$CONF" ]]; then
    echo "ERROR: $CONF not found — is Wazuh agent installed?" >&2
    exit 1
fi

echo "─── srv-dns-bind ossec.conf role-specific tuning ───"
echo
echo "Backup → $BACKUP"
cp "$CONF" "$BACKUP"

# Write the curated config to a tmp file, then atomic-move into place.
# Single heredoc to keep it audit-friendly: every line is here, nothing
# pieced together from sed transformations of unknown source.

cat > "$NEW" << 'EOF'
<!--
  SENTINEL-AI Agent Config — srv-dns-bind (10.50.0.11)
  Role: Authoritative + recursive DNS resolver (BIND 9.18) for sentinel.lab
  Curated for: thesis SOC build with Falco + Suricata + BIND query log

  See docs/per-server-configs/srv-dns-bind/ROLE.md for rationale.
-->
<ossec_config>

  <!-- ─── Manager connection ────────────────────────────────────────── -->
  <client>
    <server>
      <address>10.60.0.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu24, ubuntu24.04, sentinel-dns</config-profile>
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

  <!-- ─── Rootcheck: detect rootkits and trojaned binaries ───────────── -->
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
  </rootcheck>

  <!-- ─── System inventory (lowered to 30m on stable single-purpose host) ─── -->
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

  <!-- ─── SCA: Security Configuration Assessment baseline ─────────────── -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <!-- ─── File Integrity Monitoring ───────────────────────────────────
       Role-specific tuning:
       - Drop /usr/bin /usr/sbin /bin /sbin real-time: covered by Falco eBPF.
         Keep ONE daily scheduled scan as backup for binary-replacement
         attacks (Falco can be disabled by attacker, FIM is independent).
       - Drop /var/www, /srv: this host has no web content.
       - Drop /home, /root: covered by SSH key path which is the real risk.
       - Add real-time on /etc/bind/ and /etc/named.conf*: BIND tampering.
       - Add real-time on /etc/falco/: detection-tool tampering.
       - Add real-time on /root/.ssh/, /home/louay/.ssh/: backdoor keys.
  -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>86400</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Daily integrity check on system binaries (backup to Falco) -->
    <directories check_all="yes">/usr/bin,/usr/sbin,/bin,/sbin,/boot</directories>

    <!-- Real-time on critical config paths -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/bind</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/falco</directories>

    <!-- Real-time on SSH key paths (backdoor implantation) -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/root/.ssh</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/home/louay/.ssh</directories>

    <!-- Real-time on /tmp (attacker staging area) -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/tmp</directories>

    <!-- Routine ignores -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/resolv.conf</ignore>
    <ignore>/etc/machine-id</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$</ignore>

    <!-- Don't snapshot private keys -->
    <nodiff>/etc/ssl/private.key</nodiff>
    <nodiff type="sregex">id_rsa$|id_ed25519$|id_ecdsa$</nodiff>

    <!-- Diff feature with bounded disk quota -->
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

  <!-- ─── Log sources ─────────────────────────────────────────────────
       Role-curated list. Removed: Apache (no apache here), dpkg.log
       (no internet for package installs), pre-defined netstat/last
       commands (covered by Falco + syscollector).
  -->

  <!-- Auth: SSH attempts, sudo, login -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <!-- Syslog: systemd, kernel, AppArmor -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <!-- BIND query log (decoded by custom bind9-query decoder) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/bind/query.log</location>
  </localfile>

  <!-- BIND service log (errors, zone load failures, DoH issues) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/named/named.log</location>
  </localfile>

  <!-- Falco eBPF events (custom falco-json decoder, MITRE-tagged rules) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/falco/falco.json</location>
  </localfile>

  <!-- Active response history -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <!-- Disk usage (lowered frequency from 6m to 30m) -->
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>1800</frequency>
  </localfile>

  <!-- ─── Active Response ─────────────────────────────────────────────── -->
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

# Validate XML structure (wrapped because Wazuh files have no single root)
if ! ( echo '<root>'; cat "$NEW"; echo '</root>' ) | xmllint --noout - 2>/dev/null; then
    echo "ERROR: generated config has invalid XML — refusing to deploy" >&2
    echo "Diff vs current:" >&2
    diff "$CONF" "$NEW" | head -50 >&2
    rm -f "$NEW"
    exit 1
fi

# Atomic replace
mv "$NEW" "$CONF"
chown root:wazuh "$CONF"
chmod 660 "$CONF"

echo "Config replaced. Restarting agent..."
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

# Show diff summary
echo
echo "─── Change summary ───"
echo "Before: $(wc -l < "$BACKUP") lines"
echo "After:  $(wc -l < "$CONF") lines"
echo
echo "Active localfile blocks:"
grep -c '<localfile>' "$CONF" || true
echo
echo "Active syscheck directories:"
grep -c '<directories' "$CONF" || true
echo
echo "Recent agent log (last 10 lines):"
tail -10 /var/ossec/logs/ossec.log
echo
echo "─── Done. Verify on manager: alerts from agent 014 should still flow. ───"

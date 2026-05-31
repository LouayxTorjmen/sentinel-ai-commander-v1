#!/bin/bash
# SENTINEL-AI — srv-web ossec.conf curation
#
# Run as root on srv-web (10.50.0.12).
# Backs up the current config, applies role-specific tuning,
# verifies the agent restarts cleanly, prints a summary.
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

echo "─── srv-web ossec.conf role-specific tuning ───"
echo
echo "Backup → $BACKUP"
cp "$CONF" "$BACKUP"

cat > "$NEW" << 'EOF'
<!--
  SENTINEL-AI Agent Config — srv-web (10.50.0.12)
  Role: Apache + DVWA web application server (PHP/MySQL)
  Will also host: nginx with weak TLS cert (encrypted attack scenario)
  Curated for: thesis SOC build with Falco + Suricata + Apache + (nginx)

  See docs/per-server-configs/srv-web/ROLE.md for rationale.

  This config FIXES a malformed previous version that had two <ossec_config>
  blocks. Some localfile entries in the orphaned second block were being
  silently ignored.
-->
<ossec_config>

  <client>
    <server>
      <address>10.60.0.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu24, ubuntu24.04, sentinel-web</config-profile>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>Ubuntu-agent-web</agent_name>
      <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    </enrollment>
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

  <!-- File Integrity Monitoring
       Curated for the web-app role:
       - Real-time on /var/www/html (webshell drop detection)
       - Real-time on Apache + nginx config (tampering)
       - Real-time on TLS certificates and private keys
       - Real-time on /tmp (attacker staging)
       - Daily scheduled scan of system binaries (backup to Falco eBPF)
  -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>86400</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>

    <!-- Daily scheduled scan of system binaries -->
    <directories check_all="yes">/usr/bin,/usr/sbin,/bin,/sbin,/boot</directories>

    <!-- Real-time critical config -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/apache2</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/nginx</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/falco</directories>

    <!-- TLS material -->
    <directories realtime="yes" check_all="yes">/etc/ssl/private</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc/ssl/certs</directories>

    <!-- THE ATTACK TARGET: webshell drops, modified PHP files -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/var/www/html</directories>

    <!-- Attacker staging -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/tmp</directories>

    <!-- SSH key paths -->
    <directories realtime="yes" check_all="yes" report_changes="yes">/root/.ssh</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/home/louay/.ssh</directories>

    <!-- Routine ignores -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/machine-id</ignore>
    <ignore>/etc/resolv.conf</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$</ignore>

    <!-- Don't snapshot private keys -->
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

  <!-- ─── Log sources ───────────────────────────────────────────────────
       Curated for the web role:
       - Apache access + error: PRIMARY signal source (was missing!)
       - auth.log: SSH brute force, sudo escalation
       - syslog: systemd, kernel, AppArmor denials
       - Falco JSON: eBPF syscalls (webshell exec detection)
       - journald: covers everything else systemd-managed

       Dropped: vsftpd.log (no FTP here), dpkg.log (no internet),
       pre-built netstat/last commands (covered by syscollector + Falco).
  -->

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>

  <!-- nginx access + error (presence-tolerant: localfile silently no-ops
       if file doesn't exist yet; will activate when nginx is installed) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/falco/falco.json</location>
  </localfile>

  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <!-- Disk usage poll (lowered from 6m to 30m) -->
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

# Verify the new file is syntactically valid using Wazuh's own parser
# Don't use xmllint --noout — it rejects Wazuh's no-root multi-block files.
# Instead: have Wazuh itself test by running wazuh-control with the new
# config in test mode, BUT only on the agent side that's not great either.
# So just do a basic well-formedness check by wrapping in a fake root:
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

# Summary
echo
echo "─── Change summary ───"
echo "Before: $(wc -l < "$BACKUP") lines"
echo "After:  $(wc -l < "$CONF") lines"
echo
echo "Active <localfile> blocks: $(grep -c '<localfile>' "$CONF")"
echo "Active <directories> entries: $(grep -c '<directories' "$CONF")"
echo
echo "Recent agent log (last 10 lines):"
tail -10 /var/ossec/logs/ossec.log
echo
echo "─── Done. Verify on manager: alerts from agent 089 should still flow. ───"

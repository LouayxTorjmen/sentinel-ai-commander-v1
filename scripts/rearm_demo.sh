#!/bin/bash
# SENTINEL-AI Full Demo Re-Arm Script
# Run before every demo to restore all vulnerable baselines
set -e
echo "=== SENTINEL-AI Demo Re-Arm ==="

ANSIBLE="docker exec sentinel-ansible-runner ansible"
SSH_DNS="sshpass -p Louay2002 ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no louay@10.50.0.11"
PLAYBOOK="docker exec sentinel-ansible-runner ansible-playbook"
INV="-i /ansible/inventory/hosts.ini"

# 1) Clear iptables block on srv-web (ignore if chain doesn't exist)
echo "[1] Clearing iptables block on srv-web..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'iptables -N SENTINEL_BLOCK 2>/dev/null || true; iptables -F SENTINEL_BLOCK; echo cleared' \
  2>&1 | grep -E "CHANGED|FAILED|cleared"

# 1b) Restart Apache on srv-web (iptables flush kills connections)
echo "[1b] Restarting Apache on srv-web..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'systemctl restart apache2 && systemctl is-active apache2' \
  2>&1 | grep -E "CHANGED|FAILED|active"

# 2) Clear Windows Firewall block on srv-ad-dns
echo "[2] Clearing Windows Firewall blocks on srv-ad-dns..."
$ANSIBLE $INV srv-ad-dns -m win_shell \
  -a 'Get-NetFirewallRule -DisplayName "SentinelAI-Block-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule; echo "cleared"' \
  2>&1 | grep -E "CHANGED|FAILED|cleared"

# 3) Re-arm nginx weak TLS
echo "[3] Re-arming nginx weak TLS..."
$PLAYBOOK $INV /ansible/playbooks/setup_nginx_weak_tls.yml 2>&1 | tail -2

# 3b) Ensure Apache is running after nginx re-arm
echo "[3b] Ensuring Apache is running..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'systemctl restart apache2 && systemctl is-active apache2' \
  2>&1 | grep -E "CHANGED|FAILED|active"

# 4) Re-enable MySQL general log + restore dvwa SELECT on infra_credentials
echo "[4] Re-arming MySQL..."
$ANSIBLE $INV srv-sql -m shell \
  -a "mysql -u root -plouay -e \"
    SET GLOBAL general_log='ON';
    SET GLOBAL general_log_file='/var/log/mysql/general.log';
    GRANT SELECT ON dvwa.infra_credentials TO 'dvwa'@'%';
    FLUSH PRIVILEGES;
  \" 2>/dev/null && echo OK" \
  2>&1 | grep -E "CHANGED|FAILED|OK"

# 5) Re-arm AD CS ESC1 template
echo "[5] Re-arming AD CS ESC1 template..."
$ANSIBLE $INV srv-ad-dns -m win_shell \
  -a 'certutil -SetCATemplates +SentinelVulnESC1; echo done' \
  2>&1 | grep -E "CHANGED|FAILED|done|completed"

# 6) Remove cron backdoor
echo "[6] Removing cron backdoor..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'rm -f /etc/cron.d/sentinel-backdoor && echo cleaned' \
  2>&1 | grep -E "CHANGED|FAILED|cleaned"

# 7) Remove webshell (force fresh plant in Act 2)
echo "[7] Removing old webshell..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'rm -f /var/www/html/dvwa/hackable/uploads/sentinel_shell.php && echo cleaned' \
  2>&1 | grep -E "CHANGED|FAILED|cleaned"

# 8) Reset DVWA security level to 'impossible' so Act 2 sets it to 'low'
echo "[8] Resetting DVWA security level..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a "mysql -h 10.50.0.13 -u dvwa -pp@ssw0rd dvwa \
      -e \"UPDATE dvwa_session SET security='impossible' WHERE user='admin';\" \
      2>/dev/null && echo reset || echo skipped" \
  2>&1 | grep -E "CHANGED|FAILED|reset|skipped"


# 8b) Fix dnsdist config syntax + restore iptables DOH logging + restart
echo "[8b] Fixing dnsdist config, restoring iptables DOH rule, restarting..."
$SSH_DNS \
  "sudo iptables -F SENTINEL_BLOCK 2>/dev/null; \
   sudo iptables -N SENTINEL_DOH 2>/dev/null || sudo iptables -F SENTINEL_DOH; \
   sudo iptables -D INPUT -p tcp --dport 443 --syn -j SENTINEL_DOH 2>/dev/null || true; \
   sudo iptables -I INPUT -p tcp --dport 443 --syn -j SENTINEL_DOH; \
   sudo iptables -A SENTINEL_DOH -j LOG --log-prefix 'SENTINEL_DOH_EXFIL ' --log-level 4; \
   sudo iptables -A SENTINEL_DOH -j RETURN; \
   sudo iptables -F SENTINEL_BLOCK 2>/dev/null; \
   sudo truncate -s 0 /var/log/sentinel-doh-alert.log 2>/dev/null; \
   sudo truncate -s 0 /var/log/sentinel-doh-exfil.log 2>/dev/null; \
   sudo systemctl restart sentinel-doh-formatter 2>/dev/null; \
   echo doh_iptables_restored" 2>/dev/null \
  | grep -E "restored|failed" || true

# 8b-dnsdist) Fix dnsdist config syntax + restart on srv-dns-bind
echo "[8b] Fixing dnsdist config and restarting..."
$ANSIBLE $INV srv-dns-bind -m shell --become \
  -a 'sed -i "s/addAction(NetmaskGroupRule(newNMG():addMask(\(.*\)), DropAction())/local _nmg = newNMG(); _nmg:addMask(\1); addAction(NetmaskGroupRule(_nmg), DropAction())/g" /etc/dnsdist/dnsdist.conf && cp /etc/dnsdist/dnsdist.conf /var/lib/sentinel-ai/baselines/_etc_dnsdist_dnsdist.conf.baseline && systemctl restart dnsdist && systemctl is-active dnsdist || echo failed' \
  2>&1 | grep -E "CHANGED|FAILED|active|failed|fixed"

# 10) Re-arm Act 3 scenario state — AD accounts for AS-REP roast + Kerberoast
# 10) Re-arm Act 3 scenario state
echo "[10] Re-arming Act 3 AD scenario accounts..."
$ANSIBLE $INV srv-ad-dns -m win_shell \
  -a "Import-Module ActiveDirectory; \
      try { Set-ADAccountControl svc-legacy -DoesNotRequirePreAuth \$true; Enable-ADAccount svc-legacy; Write-Host svc-legacy-updated } \
      catch { New-ADUser -Name svc-legacy -SamAccountName svc-legacy -AccountPassword (ConvertTo-SecureString Summer2024! -AsPlainText -Force) -Enabled \$true -PasswordNeverExpires \$true; Set-ADAccountControl svc-legacy -DoesNotRequirePreAuth \$true; Write-Host svc-legacy-created }; \
      try { Set-ADAccountControl svc-mssql -DoesNotRequirePreAuth \$false; Enable-ADAccount svc-mssql; Write-Host svc-mssql-updated } \
      catch { New-ADUser -Name svc-mssql -SamAccountName svc-mssql -AccountPassword (ConvertTo-SecureString MssqlP@ss2024! -AsPlainText -Force) -Enabled \$true -PasswordNeverExpires \$true; Write-Host svc-mssql-created }; \
      \$spns=(Get-ADUser svc-mssql -Properties ServicePrincipalNames).ServicePrincipalNames; \
      if (\$spns -notcontains 'MSSQLSvc/srv-sql.mydomain.com:1433') { Set-ADUser svc-mssql -ServicePrincipalNames @{Add='MSSQLSvc/srv-sql.mydomain.com:1433'}; Write-Host SPN-registered } else { Write-Host SPN-already-set }" \
  2>&1 | grep -E "CHANGED|FAILED|created|updated|SPN"
# 11) Clean up Act 3 artifacts from previous runs on srv-web
echo "[11] Cleaning Act 3 artifacts from srv-web..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'rm -f /tmp/SENTINEL_RANSOM_NOTE.txt /tmp/exfil_bundle.tar.gz
      rm -f /tmp/sentinel_procs_*.txt /tmp/sentinel_netstat_*.txt /tmp/sentinel_auth_*.txt
      echo "cleaned"' \
  2>&1 | grep -E "CHANGED|cleaned"

# 9b) Wait for dispatcher dedup window to expire
echo "[9b] Waiting 65s for dispatcher dedup window to expire..."
sleep 65
# 9) Verify Kali can reach DVWA (most important check)
echo "[9] Verifying DVWA is reachable from outside..."
HTTP=$(curl -sS -o /dev/null -w "%{http_code}" http://10.50.0.12/dvwa/login.php 2>/dev/null || echo "FAIL")
echo "    DVWA HTTP status: $HTTP"
if [ "$HTTP" != "200" ]; then
  echo "    WARNING: DVWA not reachable! Check iptables on srv-web."
  # Force clear all iptables rules
  $ANSIBLE $INV Ubuntu-agent-web -m shell --become \
    -a 'iptables -F && iptables -X && iptables -P INPUT ACCEPT && echo "iptables reset"' \
  $ANSIBLE $INV Ubuntu-agent-web -m shell --become \
    -a 'systemctl restart apache2 && echo "apache restarted"' \
    2>&1 | grep -E "CHANGED|restarted"
    2>&1 | grep -E "CHANGED|reset"
fi

echo ""
echo "=== Re-arm complete. Ready for demo. ==="
echo "Run on Kali: sudo python3 ~/sentinel-attack-fixed/scenario.py --actor apt"

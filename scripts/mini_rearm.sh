#!/bin/bash
# Mini-rearm: clear blocks only, preserve webshell and scenario state
ANSIBLE="docker exec sentinel-ansible-runner ansible"
INV="-i /ansible/inventory/hosts.ini"

echo "=== Mini-rearm: clearing blocks ==="
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \
  -a 'iptables -F SENTINEL_BLOCK 2>/dev/null; echo ok' 2>&1 | tail -2

$ANSIBLE $INV srv-sql -m shell --become \
  -a 'iptables -F SENTINEL_BLOCK 2>/dev/null; echo ok' 2>&1 | tail -2

sshpass -p Louay2002 ssh -o StrictHostKeyChecking=no \
  -o PubkeyAuthentication=no louay@10.50.0.11 \
  'sudo iptables -F SENTINEL_BLOCK 2>/dev/null; echo ok' 2>/dev/null

$ANSIBLE $INV srv-ad-dns -m win_shell \
  -a 'Get-NetFirewallRule -DisplayName "SentinelAI-Block-*" \
      -ErrorAction SilentlyContinue | Remove-NetFirewallRule; echo cleared' \
  2>&1 | tail -2

# Verify webshell is still there
WEBSHELL=$(curl -sk \
  "http://10.50.0.12/dvwa/hackable/uploads/sentinel_shell.php?cmd=id" \
  2>/dev/null | grep -c "www-data")
if [ "$WEBSHELL" -gt 0 ]; then
  echo "✓ Webshell intact"
else
  echo "✗ Webshell missing — re-plant needed (run Act 2 first)"
fi

echo "=== Mini-rearm done ==="

#!/bin/bash
# diagnose_full.sh — run from /root/sentinel-ai-commander/
# Tells us EXACTLY why IT Hygiene and Vuln Detection are empty
SSH="ssh -i ansible/keys/id_rsa -o StrictHostKeyChecking=no -o ConnectTimeout=10"

TOKEN=$(curl -sk -X POST https://localhost:50001/security/user/authenticate \
  -u "wazuh-wui:Louay@2002" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

echo "================================================================"
echo " SENTINEL-AI Diagnostic — IT Hygiene + Vuln Detection"
echo "================================================================"
echo ""

echo "--- CHECK 1: wazuh-states-* indices in OpenSearch ---"
echo "(these are where IT Hygiene data is stored in Wazuh 4.14)"
curl -sk "https://localhost:50002/_cat/indices/wazuh-states*?h=index,docs.count,store.size&s=index" \
  -u "admin:Louay@2002"
echo ""

echo "--- CHECK 2: wazuh-vulnerabilities-* indices ---"
curl -sk "https://localhost:50002/_cat/indices/wazuh-vulnerabilities*?h=index,docs.count,store.size" \
  -u "admin:Louay@2002"
echo ""

echo "--- CHECK 3: ALL wazuh indices (see what actually exists) ---"
curl -sk "https://localhost:50002/_cat/indices?h=index,docs.count&s=index" \
  -u "admin:Louay@2002" | grep wazuh
echo ""

echo "--- CHECK 4: Manager ossec.conf — vulnerability-detection + indexer blocks ---"
docker exec sentinel-wazuh-manager grep -A 30 "vulnerability-detector\|vulnerability-detection\|<indexer>" \
  /var/ossec/etc/ossec.conf 2>/dev/null | head -60
echo ""

echo "--- CHECK 5: Manager log — inventory/syscollector activity ---"
docker exec sentinel-wazuh-manager grep -i "inventory\|syscollector\|wazuh-db\|states" \
  /var/ossec/logs/ossec.log 2>/dev/null | tail -20
echo ""

echo "--- CHECK 6: Agent 014 config on VM (confirm our file is there) ---"
$SSH root@192.168.49.128 "
  echo 'Port:'
  grep -E '<port>|<address>' /var/ossec/etc/ossec.conf
  echo 'Syscollector block:'
  grep -A 20 'syscollector' /var/ossec/etc/ossec.conf | head -25
  echo 'SCA block:'
  grep -A 5 '<sca>' /var/ossec/etc/ossec.conf | head -8
  echo 'Wazuh processes running:'
  ps aux | grep wazuh | grep -v grep | awk '{print \$11}' | sort -u
  echo 'Agent log last 15 lines:'
  tail -15 /var/ossec/logs/ossec.log
" 2>/dev/null
echo ""

echo "--- CHECK 7: wazuh-db — can we query agent inventory? ---"
docker exec sentinel-wazuh-manager bash -c "
  # wazuh-db is the local DB for agent data in Wazuh 4.x
  # IT Hygiene data flows: agent syscollector -> wazuh-db -> wazuh-states-* index
  
  # Check if wazuh-db socket is running
  ls -la /var/ossec/queue/sockets/db 2>/dev/null && echo 'DB socket exists' || echo 'DB socket missing'
  
  # Try a direct wazuh-db query for packages
  (echo 'agent 014 syscollector get_packages 0' | nc -U /var/ossec/queue/sockets/db 2>/dev/null | head -c 200) || echo 'nc query failed'
  
  # Check wazuh-db process
  ps aux | grep wazuh-db | grep -v grep | head -3
" 2>&1
echo ""

echo "--- CHECK 8: Filebeat config — does it ship states/inventory? ---"
docker exec sentinel-wazuh-manager bash -c "
  echo '=== filebeat.yml ===' 
  cat /etc/filebeat/filebeat.yml 2>/dev/null
" 2>&1
echo ""

echo "--- CHECK 9: Manager <indexer> config block ---"
docker exec sentinel-wazuh-manager bash -c "
  # Wazuh 4.14 needs an <indexer> block in manager ossec.conf 
  # to push vulnerability + inventory data to OpenSearch
  grep -A 10 '<indexer>' /var/ossec/etc/ossec.conf 2>/dev/null || echo '<indexer> BLOCK NOT FOUND IN MANAGER CONFIG'
" 2>&1
echo ""

echo "--- CHECK 10: Vulnerability feed download status ---"
docker exec sentinel-wazuh-manager bash -c "
  ls -la /var/ossec/queue/vulnerabilities/ 2>/dev/null | head -20
  echo '---'
  grep -i 'vulnerability\|CVE\|NVD\|feed' /var/ossec/logs/ossec.log 2>/dev/null | tail -15
" 2>&1

echo ""
echo "================================================================"
echo " Paste this entire output to understand the fix needed"
echo "================================================================"

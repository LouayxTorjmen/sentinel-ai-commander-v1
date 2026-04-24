#!/bin/bash
# verify_after_restart.sh — run 60s after restarting the manager
# Tells you whether IT Hygiene and Vulnerability Detection are now working

echo "================================================================"
echo " Post-restart verification"
echo "================================================================"
echo ""

echo "--- 1. inventory-harvester status in manager log ---"
docker exec sentinel-wazuh-manager grep "inventory-harvester\|InventoryHarvester" \
  /var/ossec/logs/ossec.log 2>/dev/null | tail -8
echo ""

echo "--- 2. wazuh-states-inventory-* indices (IT Hygiene data lives here) ---"
curl -sk "https://localhost:50002/_cat/indices/wazuh-states*?h=index,docs.count,store.size&s=index" \
  -u "admin:Louay@2002"
echo ""

echo "--- 3. vulnerability indices ---"
curl -sk "https://localhost:50002/_cat/indices/wazuh-vuln*?h=index,docs.count,store.size" \
  -u "admin:Louay@2002"
echo ""

echo "--- 4. Sample inventory data for one agent ---"
curl -sk "https://localhost:50002/wazuh-states-inventory-packages/_search?size=2&pretty" \
  -u "admin:Louay@2002" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
total=d.get('hits',{}).get('total',{}).get('value',0)
print(f'  Total packages indexed: {total}')
hits=d.get('hits',{}).get('hits',[])
if hits:
    src=hits[0].get('_source',{})
    print(f'  Sample: {src.get(\"name\",\"?\")} {src.get(\"version\",\"?\")} on agent {src.get(\"agent\",{}).get(\"name\",\"?\")}')
" 2>/dev/null || echo "  Index may not exist yet — wait 2 more minutes"
echo ""

echo "--- 5. inventory-harvester config in running container ---"
docker exec sentinel-wazuh-manager grep -A5 "inventory-harvester" /var/ossec/etc/ossec.conf
echo ""

echo "--- 6. RHEL vulnerability provider in running container ---"
docker exec sentinel-wazuh-manager grep -A5 '"redhat"\|"almalinux"' /var/ossec/etc/ossec.conf
echo ""

echo "--- 7. Vulnerability feed download status ---"
docker exec sentinel-wazuh-manager bash -c "
  ls -la /var/ossec/queue/vulnerabilities/ 2>/dev/null | head -10 || echo 'Dir not found'
  grep -i 'vulnerability\|CVE\|feed\|NVD' /var/ossec/logs/ossec.log 2>/dev/null | tail -10
" 2>&1

echo ""
echo "================================================================"
echo "If wazuh-states-inventory-* indices show docs.count > 0 → IT Hygiene fixed"
echo "If still 0 after 3 min, agent data not reaching harvester yet"
echo "================================================================"

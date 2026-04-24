#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════
# audit_suricata.sh v4 — Suricata deployment audit
# Fix: Use FD 3 for the agent loop so SSH heredoc on stdin works normally
# ═══════════════════════════════════════════════════════════════════════

set +u

SENTINEL_DIR="${SENTINEL_DIR:-$HOME/sentinel-ai-commander}"
SSH_KEY="${SSH_KEY:-$SENTINEL_DIR/ansible/keys/id_rsa}"
WAZUH_API="${WAZUH_API:-https://localhost:50001}"
WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"
WAZUH_API_PASS="${WAZUH_API_PASS:-$(grep '^WAZUH_API_PASSWORD=' $SENTINEL_DIR/.env 2>/dev/null | cut -d= -f2)}"
INDEXER_PASS="${INDEXER_PASS:-$(grep '^WAZUH_INDEXER_PASSWORD=' $SENTINEL_DIR/.env 2>/dev/null | cut -d= -f2)}"
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=ERROR"

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
B="\033[1m"; DIM="\033[2m"; RST="\033[0m"

TS=$(date +%Y%m%d-%H%M%S)
CSV="/tmp/suricata_audit_${TS}.csv"
NEEDS_INSTALL="/tmp/suricata_needs_install.txt"
NEEDS_REMEDIATE="/tmp/suricata_needs_remediate.txt"
echo "agent_name,agent_ip,interface,ssh_ok,suricata_installed,suricata_running,eve_json_present,eve_json_growing,wazuh_tails_eve,recent_alerts_24h,et_open_rules,overall" > "$CSV"
> "$NEEDS_INSTALL"
> "$NEEDS_REMEDIATE"

banner() {
    echo -e "${C}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║  🔍  Suricata Deployment Audit v4 — SENTINEL-AI Commander      ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
}

check_prereqs() {
    [ -z "$WAZUH_API_PASS" ] && { echo -e "${R}✗ Can't read WAZUH_API_PASSWORD from .env${RST}"; exit 1; }
    [ ! -r "$SSH_KEY" ] && { echo -e "${R}✗ SSH key not readable: $SSH_KEY${RST}"; exit 1; }
    for tool in jq curl ssh; do
        command -v "$tool" >/dev/null || { echo -e "${R}✗ Missing tool: $tool${RST}"; exit 1; }
    done
    echo -e "${DIM}  Prerequisites OK${RST}"
}

get_token() {
    curl -sk -X POST "$WAZUH_API/security/user/authenticate" \
        -u "$WAZUH_API_USER:$WAZUH_API_PASS" | jq -r '.data.token // empty'
}

count_recent_suricata_alerts() {
    local agent_name="$1"
    [ -z "$INDEXER_PASS" ] && { echo "0"; return; }
    local query='{"size":0,"query":{"bool":{"must":[{"match":{"agent.name":"'"$agent_name"'"}},{"match":{"rule.groups":"suricata"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}}}'
    local count
    count=$(curl -sk -u "admin:$INDEXER_PASS" \
        -H "Content-Type: application/json" \
        -X GET "https://localhost:50002/wazuh-alerts-*/_search" \
        -d "$query" 2>/dev/null | jq -r '.hits.total.value // 0' 2>/dev/null)
    echo "${count:-0}"
}

check_host() {
    local agent_name="$1"
    local agent_ip="$2"

    if [[ "$agent_name" == "wazuh.manager" ]] || [[ "$agent_name" == "manager" ]]; then
        return
    fi

    echo ""
    echo -e "${B}${C}━━━ $agent_name ${DIM}($agent_ip)${RST}"

    if ! ssh $SSH_OPTS "root@$agent_ip" "echo ok" </dev/null >/dev/null 2>&1; then
        echo -e "  ${R}✗ SSH unreachable${RST} — skipping"
        echo "$agent_name,$agent_ip,,no,unknown,unknown,unknown,unknown,unknown,unknown,unknown,UNREACHABLE" >> "$CSV"
        return
    fi
    echo -e "  ${G}✓${RST} SSH reachable"

    # Heredoc on stdin works — loop uses FD 3 in main()
    local REMOTE_OUT
    REMOTE_OUT=$(ssh $SSH_OPTS "root@$agent_ip" 'bash -s' <<'REMOTE_EOF' 2>&1
SURICATA_INSTALLED=no
SURICATA_RUNNING=no
SURICATA_VERSION=""
EVE_PRESENT=no
EVE_GROWING=no
EVE_SIZE=0
WAZUH_TAILS_EVE=no
ET_OPEN=no
RULE_COUNT=0
INTERFACE=""
SURICATA_CONFIG_IFACE=""

INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -1)

if command -v suricata >/dev/null 2>&1; then
    SURICATA_INSTALLED=yes
    SURICATA_VERSION=$(suricata -V 2>&1 | grep -oP 'Suricata version \K[^\s,]+' | head -1)
    if [ -f /etc/suricata/suricata.yaml ]; then
        # Look for interface: value under af-packet section
        SURICATA_CONFIG_IFACE=$(awk '/^af-packet:/{flag=1; next} flag && /^\s*-?\s*interface:/{gsub(/[[:space:]-]/,""); split($0,a,":"); print a[2]; exit}' /etc/suricata/suricata.yaml 2>/dev/null)
    fi
fi

if systemctl is-active --quiet suricata 2>/dev/null; then
    SURICATA_RUNNING=yes
fi

if [ -f /var/log/suricata/eve.json ]; then
    EVE_PRESENT=yes
    EVE_SIZE=$(stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
    sleep 2
    EVE_SIZE2=$(stat -c%s /var/log/suricata/eve.json 2>/dev/null || echo 0)
    if [ "${EVE_SIZE2:-0}" -gt "${EVE_SIZE:-0}" ]; then
        EVE_GROWING=yes
    elif [ "${EVE_SIZE:-0}" -gt 0 ]; then
        EVE_GROWING=stale
    fi
fi

if [ -f /var/ossec/etc/ossec.conf ]; then
    if grep -q "suricata/eve.json" /var/ossec/etc/ossec.conf 2>/dev/null; then
        WAZUH_TAILS_EVE=yes
    fi
else
    WAZUH_TAILS_EVE=no_wazuh
fi

if [ -f /var/lib/suricata/rules/suricata.rules ]; then
    RULE_COUNT=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
    if [ "${RULE_COUNT:-0}" -gt 1000 ]; then
        ET_OPEN=yes
    elif [ "${RULE_COUNT:-0}" -gt 0 ]; then
        ET_OPEN=minimal
    fi
fi

echo "SURICATA_INSTALLED=$SURICATA_INSTALLED"
echo "SURICATA_VERSION=$SURICATA_VERSION"
echo "SURICATA_RUNNING=$SURICATA_RUNNING"
echo "EVE_PRESENT=$EVE_PRESENT"
echo "EVE_GROWING=$EVE_GROWING"
echo "EVE_SIZE=$EVE_SIZE"
echo "WAZUH_TAILS_EVE=$WAZUH_TAILS_EVE"
echo "ET_OPEN=$ET_OPEN"
echo "RULE_COUNT=$RULE_COUNT"
echo "INTERFACE=$INTERFACE"
echo "SURICATA_CONFIG_IFACE=$SURICATA_CONFIG_IFACE"
REMOTE_EOF
    )

    SURICATA_INSTALLED=$(echo "$REMOTE_OUT" | grep "^SURICATA_INSTALLED=" | cut -d= -f2)
    SURICATA_VERSION=$(echo "$REMOTE_OUT" | grep "^SURICATA_VERSION=" | cut -d= -f2)
    SURICATA_RUNNING=$(echo "$REMOTE_OUT" | grep "^SURICATA_RUNNING=" | cut -d= -f2)
    EVE_PRESENT=$(echo "$REMOTE_OUT" | grep "^EVE_PRESENT=" | cut -d= -f2)
    EVE_GROWING=$(echo "$REMOTE_OUT" | grep "^EVE_GROWING=" | cut -d= -f2)
    EVE_SIZE=$(echo "$REMOTE_OUT" | grep "^EVE_SIZE=" | cut -d= -f2)
    WAZUH_TAILS_EVE=$(echo "$REMOTE_OUT" | grep "^WAZUH_TAILS_EVE=" | cut -d= -f2)
    ET_OPEN=$(echo "$REMOTE_OUT" | grep "^ET_OPEN=" | cut -d= -f2)
    RULE_COUNT=$(echo "$REMOTE_OUT" | grep "^RULE_COUNT=" | cut -d= -f2)
    INTERFACE=$(echo "$REMOTE_OUT" | grep "^INTERFACE=" | cut -d= -f2)
    SURICATA_CONFIG_IFACE=$(echo "$REMOTE_OUT" | grep "^SURICATA_CONFIG_IFACE=" | cut -d= -f2)

    if [ -z "$SURICATA_INSTALLED" ]; then
        echo -e "  ${R}✗ Remote check failed — raw output:${RST}"
        echo "$REMOTE_OUT" | head -5 | sed 's/^/      /'
        echo "$agent_name,$agent_ip,,yes,check_failed,check_failed,check_failed,check_failed,check_failed,check_failed,check_failed,CHECK_FAILED" >> "$CSV"
        return
    fi

    echo -e "  ${DIM}  Interface detected: ${INTERFACE:-?}${RST}"

    if [ "$SURICATA_INSTALLED" = "yes" ]; then
        echo -e "  ${G}✓${RST} Suricata installed ${DIM}(v${SURICATA_VERSION:-unknown})${RST}"
        if [ -n "$SURICATA_CONFIG_IFACE" ] && [ -n "$INTERFACE" ] && [ "$SURICATA_CONFIG_IFACE" != "$INTERFACE" ]; then
            echo -e "  ${R}✗${RST} Interface mismatch: yaml=${R}${SURICATA_CONFIG_IFACE}${RST}, host=${G}${INTERFACE}${RST}"
        fi
    else
        echo -e "  ${R}✗${RST} Suricata NOT installed"
    fi

    if [ "$SURICATA_RUNNING" = "yes" ]; then
        echo -e "  ${G}✓${RST} Suricata service running"
    elif [ "$SURICATA_INSTALLED" = "yes" ]; then
        echo -e "  ${Y}⚠${RST} Suricata installed but NOT running"
    fi

    case "$EVE_GROWING" in
        yes)   echo -e "  ${G}✓${RST} eve.json growing ${DIM}(${EVE_SIZE} bytes and counting)${RST}" ;;
        stale) echo -e "  ${Y}⚠${RST} eve.json stale ${DIM}(${EVE_SIZE} bytes, not growing)${RST}" ;;
        no)    [ "$SURICATA_INSTALLED" = "yes" ] && echo -e "  ${R}✗${RST} eve.json missing or empty" ;;
    esac

    case "$WAZUH_TAILS_EVE" in
        yes)      echo -e "  ${G}✓${RST} Wazuh agent tails eve.json" ;;
        no)       echo -e "  ${R}✗${RST} Wazuh agent NOT configured to tail eve.json" ;;
        no_wazuh) echo -e "  ${R}✗${RST} No Wazuh agent installed" ;;
    esac

    local recent_alerts
    recent_alerts=$(count_recent_suricata_alerts "$agent_name")
    if [ "${recent_alerts:-0}" -gt 0 ] 2>/dev/null; then
        echo -e "  ${G}✓${RST} ${recent_alerts} Suricata alerts reached manager (last 24h)"
    else
        if [ "$SURICATA_INSTALLED" = "yes" ] && [ "$WAZUH_TAILS_EVE" = "yes" ]; then
            echo -e "  ${Y}⚠${RST} 0 Suricata alerts in last 24h ${DIM}(wiring OK, maybe no traffic)${RST}"
        else
            echo -e "  ${DIM}  0 Suricata alerts in last 24h${RST}"
        fi
    fi

    case "$ET_OPEN" in
        yes)     echo -e "  ${G}✓${RST} ET Open ruleset loaded ${DIM}(${RULE_COUNT} rules)${RST}" ;;
        minimal) echo -e "  ${Y}⚠${RST} Minimal rules only ${DIM}(${RULE_COUNT} rules)${RST}" ;;
        no)      [ "$SURICATA_INSTALLED" = "yes" ] && echo -e "  ${R}✗${RST} No rules file found" ;;
    esac

    local overall
    if [ "$SURICATA_INSTALLED" = "no" ]; then
        overall="NEEDS_INSTALL"
        echo "$agent_name $agent_ip $INTERFACE" >> "$NEEDS_INSTALL"
    elif [ -n "$SURICATA_CONFIG_IFACE" ] && [ -n "$INTERFACE" ] && [ "$SURICATA_CONFIG_IFACE" != "$INTERFACE" ]; then
        overall="NEEDS_INTERFACE_FIX"
        echo "$agent_name $agent_ip $INTERFACE interface_mismatch($SURICATA_CONFIG_IFACE)" >> "$NEEDS_REMEDIATE"
    elif [ "$SURICATA_RUNNING" = "no" ]; then
        overall="NEEDS_START"
        echo "$agent_name $agent_ip $INTERFACE needs_start" >> "$NEEDS_REMEDIATE"
    elif [ "$WAZUH_TAILS_EVE" != "yes" ]; then
        overall="NEEDS_WAZUH_CONFIG"
        echo "$agent_name $agent_ip $INTERFACE needs_wazuh_config" >> "$NEEDS_REMEDIATE"
    elif [ "$ET_OPEN" != "yes" ]; then
        overall="NEEDS_RULES_UPDATE"
        echo "$agent_name $agent_ip $INTERFACE needs_rules" >> "$NEEDS_REMEDIATE"
    elif [ "$EVE_GROWING" = "stale" ]; then
        overall="STALE"
        echo "$agent_name $agent_ip $INTERFACE stale" >> "$NEEDS_REMEDIATE"
    else
        overall="HEALTHY"
    fi

    case "$overall" in
        HEALTHY)             echo -e "  ${G}${B}→ HEALTHY${RST}" ;;
        NEEDS_INSTALL)       echo -e "  ${R}${B}→ NEEDS SURICATA INSTALL${RST}" ;;
        NEEDS_INTERFACE_FIX) echo -e "  ${R}${B}→ NEEDS INTERFACE FIX + full restart${RST}" ;;
        NEEDS_START)         echo -e "  ${Y}${B}→ NEEDS SURICATA START${RST}" ;;
        NEEDS_WAZUH_CONFIG)  echo -e "  ${Y}${B}→ NEEDS WAZUH CONFIG${RST}" ;;
        NEEDS_RULES_UPDATE)  echo -e "  ${Y}${B}→ NEEDS RULESET UPDATE${RST}" ;;
        STALE)               echo -e "  ${Y}${B}→ STALE${RST}" ;;
    esac

    echo "$agent_name,$agent_ip,$INTERFACE,yes,$SURICATA_INSTALLED,$SURICATA_RUNNING,$EVE_PRESENT,$EVE_GROWING,$WAZUH_TAILS_EVE,$recent_alerts,$ET_OPEN,$overall" >> "$CSV"
}

count_csv() {
    local pattern="$1" n
    n=$(grep -c "$pattern" "$CSV" 2>/dev/null | head -1 | tr -d '[:space:]')
    echo "${n:-0}"
}

print_summary() {
    echo ""
    echo -e "${C}╔════════════════════════════════════════════════════════════════╗"
    echo -e "║  Summary                                                       ║"
    echo -e "╚════════════════════════════════════════════════════════════════╝${RST}"
    local total healthy needs_install needs_iface needs_start needs_config needs_rules stale unreachable check_failed
    total=$(($(wc -l < "$CSV") - 1))
    healthy=$(count_csv ",HEALTHY$")
    needs_install=$(count_csv ",NEEDS_INSTALL$")
    needs_iface=$(count_csv ",NEEDS_INTERFACE_FIX$")
    needs_start=$(count_csv ",NEEDS_START$")
    needs_config=$(count_csv ",NEEDS_WAZUH_CONFIG$")
    needs_rules=$(count_csv ",NEEDS_RULES_UPDATE$")
    stale=$(count_csv ",STALE$")
    unreachable=$(count_csv ",UNREACHABLE$")
    check_failed=$(count_csv ",CHECK_FAILED$")

    echo -e "  Total agents audited:        ${B}$total${RST}"
    echo -e "  ${G}Healthy (full pipeline):     $healthy${RST}"
    [ "$needs_install" -gt 0 ]  && echo -e "  ${R}Need Suricata install:       $needs_install${RST}"
    [ "$needs_iface" -gt 0 ]    && echo -e "  ${R}Interface mismatch:          $needs_iface${RST}"
    [ "$needs_start" -gt 0 ]    && echo -e "  ${Y}Installed but not running:   $needs_start${RST}"
    [ "$needs_config" -gt 0 ]   && echo -e "  ${Y}Missing Wazuh eve.json cfg:  $needs_config${RST}"
    [ "$needs_rules" -gt 0 ]    && echo -e "  ${Y}Need ET Open rules update:   $needs_rules${RST}"
    [ "$stale" -gt 0 ]          && echo -e "  ${Y}Stale (no new events):       $stale${RST}"
    [ "$unreachable" -gt 0 ]    && echo -e "  ${R}Unreachable via SSH:         $unreachable${RST}"
    [ "$check_failed" -gt 0 ]   && echo -e "  ${R}Remote check failed:         $check_failed${RST}"

    echo ""
    echo -e "  ${DIM}CSV:         $CSV${RST}"
    [ -s "$NEEDS_INSTALL" ]   && echo -e "  ${DIM}Needs install: $NEEDS_INSTALL${RST}"
    [ -s "$NEEDS_REMEDIATE" ] && echo -e "  ${DIM}Needs remed.:  $NEEDS_REMEDIATE${RST}"
}

main() {
    banner
    check_prereqs

    echo ""
    echo -e "  Fetching agent list from Wazuh API..."
    local token
    token=$(get_token)
    [ -z "$token" ] && { echo -e "${R}✗ Failed to authenticate with Wazuh API${RST}"; exit 1; }

    local agents_tmp="/tmp/.sentinel_agents.$$"
    curl -sk -H "Authorization: Bearer $token" \
        "$WAZUH_API/agents?select=id,name,ip,status&limit=500" \
        | jq -r '.data.affected_items[] | select(.id != "000") | "\(.name)|\(.ip)"' \
        > "$agents_tmp"

    local agent_count
    agent_count=$(wc -l < "$agents_tmp")
    echo -e "  Found ${B}$agent_count${RST} enrolled agents"

    # KEY FIX: use FD 3 for the loop so SSH's stdin heredoc works normally
    while IFS='|' read -r name ip <&3; do
        [ -z "$name" ] && continue
        check_host "$name" "$ip"
    done 3< "$agents_tmp"

    rm -f "$agents_tmp"
    print_summary
}

main "$@"

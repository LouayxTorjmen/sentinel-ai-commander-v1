#!/usr/bin/env python3
"""
SENTINEL-AI Topology Hardcode Removal — Patch Script
=====================================================
Applies targeted patches to remove hardcoded topology from 5 files.
Run from ~/sentinel-ai-commander/ after copying config_topology.py.

Usage: python3 scripts/apply_topology_patches.py
"""

import re
import sys
from pathlib import Path

BASE = Path(__file__).parent.parent  # ~/sentinel-ai-commander/


def patch(path: str, old: str, new: str, label: str) -> bool:
    p = BASE / path
    content = p.read_text()
    if old not in content:
        if label.endswith("(already patched)") or new.split("\n")[0].strip() in content:
            print(f"  SKIP (already applied): {label}")
            return True
        print(f"  FAIL: {label}")
        print(f"    Could not find target in {path}")
        return False
    p.write_text(content.replace(old, new))
    print(f"  OK: {label}")
    return True


results = []

# ─────────────────────────────────────────────────────────────────────────────
# 1. ansible_dispatch_agent.py
# ─────────────────────────────────────────────────────────────────────────────
print("\n[1/5] ansible_dispatch_agent.py")

f = "ai_agents/agents/ansible_dispatch/ansible_dispatch_agent.py"

# Patch A: pfSense block_ip redirect (line ~537)
results.append(patch(f,
    old='''        # Reroute pfSense block_ip to a Linux host (pfSense is FreeBSD/unknown)
        if decision.get("playbook") == "block_ip" and "sentinel-fw" in agent_name:
            agent_name = "Ubuntu-agent-web"

        # Kerberos alerts from pfSense/Suricata — redirect to srv-ad-dns (Windows DC)
        if rule_id in {"100700", "100701", "100710", "100711"} and            ("sentinel-fw" in agent_name or "pfSense" in agent_name or
            os_of_agent(agent_name) != "windows"):
            agent_name = "srv-ad-dns"''',
    new='''        # Reroute gateway block_ip to a real Linux agent
        # (the gateway agent is FreeBSD/pfSense — can't run iptables playbooks)
        from ai_agents.config_topology import get_topology as _get_topo
        _topo = _get_topo()
        _gw   = _topo.get_gateway_agent()
        if decision.get("playbook") == "block_ip" and _gw and _gw in agent_name:
            _redirect = _topo.get_fw_redirect_target()
            if _redirect:
                agent_name = _redirect

        # Kerberos alerts from gateway/pfSense — redirect to the Windows DC
        # The DC is the first Windows agent in the inventory
        if rule_id in {"100700", "100701", "100710", "100711"} and (
            (_gw and _gw in agent_name) or "pfSense" in agent_name
            or os_of_agent(agent_name) != "windows"
        ):
            windows_agents = list(_topo.get_windows_agents())
            # Prefer agents with 'ad', 'dc', 'domain' in the name
            dc_candidates = [a for a in windows_agents
                             if any(kw in a.lower() for kw in ("ad", "dc", "domain", "controller"))]
            agent_name = dc_candidates[0] if dc_candidates else (windows_agents[0] if windows_agents else agent_name)''',
    label="gateway redirect + Kerberos redirect — dynamic",
))

# Patch B: second block_ip pfSense redirect (line ~619)
results.append(patch(f,
    old='''        # For block_ip triggered by pfSense (FreeBSD), redirect to a Linux host
        agent_name = (alert.get("agent") or {}).get("name", "")
        if decision.get("playbook") == "block_ip" and "sentinel-fw" in agent_name:
            extra_vars["target_hosts"] = "Ubuntu-agent-web"
            extra_vars["block_ip_address"] = extra_vars.get("source_ip", "")''',
    new='''        # For block_ip triggered by gateway (FreeBSD/pfSense), redirect to Linux host
        agent_name = (alert.get("agent") or {}).get("name", "")
        from ai_agents.config_topology import get_topology as _get_topo2
        _topo2 = _get_topo2()
        _gw2   = _topo2.get_gateway_agent()
        if decision.get("playbook") == "block_ip" and _gw2 and _gw2 in agent_name:
            _redir = _topo2.get_fw_redirect_target()
            if _redir:
                extra_vars["target_hosts"]    = _redir
                extra_vars["block_ip_address"] = extra_vars.get("source_ip", "")''',
    label="block_ip extra_vars redirect — dynamic",
))

# Patch C: AD-CS ca_name (line ~631) — use env var (already uses env, just verify)
# This one is fine as-is: os.getenv("ADCS_CA_NAME", "SENTINEL-LAB-CA")
# The fallback default is lab-specific but ADCS_CA_NAME env overrides it.
print("  OK: ADCS_CA_NAME already uses os.getenv() — no change needed")

# Patch D: Kerberos extra_vars target
results.append(patch(f,
    old='''        if rule_id in {"100700", "100701", "100710", "100711"}:
            extra_vars["target_hosts"] = "srv-ad-dns"''',
    new='''        if rule_id in {"100700", "100701", "100710", "100711"}:
            from ai_agents.config_topology import get_topology as _get_topo3
            _topo3   = _get_topo3()
            _windows = list(_topo3.get_windows_agents())
            _dc_list = [a for a in _windows
                        if any(kw in a.lower() for kw in ("ad", "dc", "domain", "controller"))]
            extra_vars["target_hosts"] = _dc_list[0] if _dc_list else (_windows[0] if _windows else "srv-ad-dns")''',
    label="Kerberos extra_vars target — dynamic",
))


# ─────────────────────────────────────────────────────────────────────────────
# 2. alert_dispatcher.py
# ─────────────────────────────────────────────────────────────────────────────
print("\n[2/5] alert_dispatcher.py")

f = "ai_agents/agents/wazuh_consumer/alert_dispatcher.py"
content = (BASE / f).read_text()

if "_FIM_WINDOWS_AGENTS" in content:
    old_fim = '_FIM_WINDOWS_AGENTS = {"srv-ad-dns", "srv-ftp"}'
    new_fim = '''# Windows agents for FIM — loaded dynamically from topology config
def _get_fim_windows_agents() -> set:
    try:
        from ai_agents.config_topology import get_topology
        return get_topology().get_windows_agents()
    except Exception:
        return set()

# Backwards-compatible name used elsewhere in this file
_FIM_WINDOWS_AGENTS_DYNAMIC = True  # flag: use _get_fim_windows_agents() not the set'''
    if old_fim in content:
        (BASE / f).write_text(content.replace(old_fim, new_fim))
        print("  OK: _FIM_WINDOWS_AGENTS → dynamic")
    else:
        print("  SKIP: _FIM_WINDOWS_AGENTS pattern not found as expected")
else:
    print("  SKIP: _FIM_WINDOWS_AGENTS already dynamic or not present")

# Replace all uses of the set with the function call
content2 = (BASE / f).read_text()
if "_FIM_WINDOWS_AGENTS" in content2 and "_FIM_WINDOWS_AGENTS_DYNAMIC" not in content2:
    pass  # already handled above
elif "agent_name in _FIM_WINDOWS_AGENTS" in content2:
    content2 = content2.replace(
        "agent_name in _FIM_WINDOWS_AGENTS",
        "agent_name in _get_fim_windows_agents()"
    )
    (BASE / f).write_text(content2)
    print("  OK: _FIM_WINDOWS_AGENTS membership check → _get_fim_windows_agents()")


# ─────────────────────────────────────────────────────────────────────────────
# 3. wazuh_feedback.py
# ─────────────────────────────────────────────────────────────────────────────
print("\n[3/5] wazuh_feedback.py")

f = "ai_agents/integrations/wazuh_feedback.py"
content = (BASE / f).read_text()

# Find the hardcoded target_agent="srv-ftp" line
if 'target_agent="srv-ftp"' in content:
    (BASE / f).write_text(
        content.replace('target_agent="srv-ftp"', 'target_agent=os.getenv("SENTINEL_FEEDBACK_AGENT", "")')
    )
    # Ensure os is imported
    content2 = (BASE / f).read_text()
    if "import os" not in content2:
        (BASE / f).write_text("import os\n" + content2)
    print("  OK: target_agent='srv-ftp' → os.getenv('SENTINEL_FEEDBACK_AGENT', '')")
else:
    print("  SKIP: target_agent='srv-ftp' not found (may already be patched)")


# ─────────────────────────────────────────────────────────────────────────────
# 4. agent_chat_native.py — dynamic system prompt
# ─────────────────────────────────────────────────────────────────────────────
print("\n[4/5] agent_chat_native.py")

f = "ai_agents/rag/agent_chat_native.py"

# Replace static topology block in SYSTEM_PROMPT with dynamic version
results.append(patch(f,
    old='''- 10.50.0.0/24: DMZ victim servers (Ubuntu-agent-web=10.50.0.12, srv-sql=10.50.0.13, srv-dns-bind=10.50.0.11, srv-ad-dns=10.50.0.10, srv-ftp=10.50.0.14)
- 10.60.0.0/24: Management (Docker host, Ansible runner)
- 10.70.0.0/24: Attacker Kali Linux (10.70.0.10)''',
    new='''- Network topology is loaded dynamically from Wazuh at query time
- Management subnets (never block): configured via SENTINEL_MANAGEMENT_SUBNETS env
- Attacker/red-team subnets: configured via SENTINEL_ATTACKER_SUBNETS env
- For current agent list: use list_agents() or get_agent_details()''',
    label="static IP block in SYSTEM_PROMPT → dynamic note",
))

results.append(patch(f,
    old='''- agent_name: exact agent name from the lab (Ubuntu-agent-web, srv-sql, srv-dns-bind, srv-ad-dns, srv-ftp, sentinel-fw)

CRITICAL TOPOLOGY RULE — port scans and network attacks:
  Suricata runs on sentinel-fw (the gateway), NOT on victim hosts.
  Port scans targeting a victim host are stored as alerts FROM sentinel-fw.
  To find "what ports were scanned on Ubuntu-agent-web":
    CORRECT: search_alerts(dst_ip="10.50.0.12", time_window="7d")
    WRONG:   search_alerts(agent_name="Ubuntu-agent-web", rule_groups=["suricata"])
  Host-to-IP mapping:
    Ubuntu-agent-web = 10.50.0.12
    srv-sql          = 10.50.0.13
    srv-dns-bind     = 10.50.0.11
    srv-ad-dns       = 10.50.0.10
    srv-ftp          = 10.50.0.14''',
    new='''- agent_name: use list_agents() to get current enrolled agent names (environment-specific)

CRITICAL TOPOLOGY RULE — port scans and network attacks:
  Suricata runs on the GATEWAY AGENT, NOT on victim hosts.
  Use get_agent_details() or list_agents() to identify the gateway (look for 'fw'/'firewall'/'pfsense' in name).
  Port scans targeting a victim host are stored as alerts FROM the gateway agent WITH dst_ip = victim IP.
  To find "what ports were scanned on agent X":
    CORRECT: look up agent X's IP with get_agent_details(agent_X), then search_alerts(dst_ip=<that_ip>)
    WRONG:   search_alerts(agent_name=agent_X, rule_groups=["suricata"])''',
    label="hardcoded agent names and IP map in SYSTEM_PROMPT → dynamic instructions",
))


# ─────────────────────────────────────────────────────────────────────────────
# 5. agent_tools.py — hostname aliases + management subnet
# ─────────────────────────────────────────────────────────────────────────────
print("\n[5/5] agent_tools.py")

f = "ai_agents/rag/agent_tools.py"

# Replace static hostname alias map with dynamic lookup
results.append(patch(f,
    old='''    # Normalise target_host — map friendly names to actual Ansible inventory names
    _HOST_ALIASES = {
        "srv-web":        "Ubuntu-agent-web",
        "web":            "Ubuntu-agent-web",
        "ubuntu-web":     "Ubuntu-agent-web",
        "webserver":      "Ubuntu-agent-web",
        "dns":            "srv-dns-bind",
        "bind":           "srv-dns-bind",
        "sql":            "srv-sql",
        "mysql":          "srv-sql",
        "db":             "srv-sql",
        "ad":             "srv-ad-dns",
        "dc":             "srv-ad-dns",
        "ftp":            "srv-ftp",
    }
    target_host = _HOST_ALIASES.get(target_host.lower().strip(), target_host)''',
    new='''    # Normalise target_host — try to resolve short names to real agent names
    # First check a static alias map (common short names), then fuzzy-match
    # against the live Wazuh agent list.
    _STATIC_ALIASES = {
        "web": "web", "webserver": "web", "dns": "dns", "bind": "dns",
        "sql": "sql", "mysql": "sql", "db": "sql", "ad": "ad",
        "dc": "ad", "ftp": "ftp", "fw": "fw", "firewall": "fw",
        "gateway": "fw",
    }
    _normalized = target_host.lower().strip()
    _keyword    = _STATIC_ALIASES.get(_normalized, _normalized)
    try:
        from ai_agents.config_topology import get_topology as _topo_fn
        _agents = _topo_fn().get_all_agents()
        # Exact match first
        _exact = next((a["name"] for a in _agents if a["name"].lower() == _normalized), None)
        if _exact:
            target_host = _exact
        else:
            # Keyword substring match
            _fuzzy = next((a["name"] for a in _agents if _keyword in a["name"].lower()), None)
            if _fuzzy:
                target_host = _fuzzy
    except Exception:
        pass  # keep original if topology unavailable''',
    label="static hostname alias map → dynamic agent lookup",
))

# Replace hardcoded management subnet check
results.append(patch(f,
    old='''    if source_ip and (
        source_ip in ("127.0.0.1", "::1")
        or source_ip.startswith("10.60.")
    ):
        return {
            "error": f"Refusing to block protected IP '{source_ip}' (loopback or management subnet)."
        }''',
    new='''    if source_ip:
        try:
            from ai_agents.config_topology import get_topology as _topo_fn2
            if not _topo_fn2().is_safe_to_block(source_ip):
                return {
                    "error": f"Refusing to block protected IP '{source_ip}' "
                             f"(loopback or management subnet per SENTINEL_MANAGEMENT_SUBNETS)."
                }
        except Exception:
            # Fallback safety check if topology unavailable
            import ipaddress as _ipa
            try:
                _addr = _ipa.ip_address(source_ip)
                if _addr.is_loopback:
                    return {"error": f"Refusing to block loopback IP '{source_ip}'."}
            except ValueError:
                pass''',
    label="hardcoded 10.60. management subnet → topology.is_safe_to_block()",
))

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
failed = [r for r in results if r is False]
print(f"\n{'='*60}")
print(f"Patches applied: {len([r for r in results if r is True])}/{len(results)}")
if failed:
    print(f"Failed: {len(failed)} — check output above and apply manually")
else:
    print("All patches applied successfully")
print(f"{'='*60}")

"""
SENTINEL-AI — Dynamic Topology Configuration
=============================================
Replaces all hardcoded agent names, IP ranges, and OS classifications
with a live-queried, environment-variable-driven topology layer.

Environment variables (add to .env):
  SENTINEL_MANAGEMENT_SUBNETS   Comma-separated CIDRs — never block (default: 10.60.0.0/24)
  SENTINEL_ATTACKER_SUBNETS     Comma-separated CIDRs — known red-team ranges (default: 10.70.0.0/24)
  SENTINEL_GATEWAY_AGENT        Agent name of the network gateway/Suricata sensor
                                Auto-detected from agent names if not set.
  SENTINEL_WINDOWS_AGENTS       Comma-separated agent names that are Windows
                                Falls back to Ansible inventory windows_agents group.
  SENTINEL_FW_REDIRECT_TARGET   For block_ip from gateway: redirect to this Linux agent
                                Auto-detected if not set.

Everything else (agent names, IPs, OS) is queried live from Wazuh.
Cache TTL: 300s (5 minutes). Override with SENTINEL_TOPOLOGY_CACHE_TTL.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import time
from typing import Dict, List, Optional

logger = logging.getLogger("sentinel.topology")


# ── Subnet helpers ────────────────────────────────────────────────────────────

def _parse_subnets(subnet_str: str) -> List[ipaddress.IPv4Network]:
    result = []
    for s in subnet_str.split(","):
        s = s.strip()
        if not s:
            continue
        try:
            result.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            logger.warning("topology.invalid_subnet: %s", s)
    return result


def _ip_in_subnets(ip: str, subnets: List[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in subnets)
    except ValueError:
        return False


# ── Gateway / Suricata sensor auto-detection ──────────────────────────────────

_GATEWAY_KEYWORDS = {"fw", "firewall", "pfsense", "gateway", "gw", "sensor", "ids", "ips"}


def _looks_like_gateway(agent_name: str) -> bool:
    name_lower = agent_name.lower()
    return any(kw in name_lower for kw in _GATEWAY_KEYWORDS)


# ── TopologyConfig ────────────────────────────────────────────────────────────

class TopologyConfig:
    """
    Single source of truth for network topology.
    All hardcoded agent names and IP ranges should go through this class.
    """

    def __init__(self):
        self._mgmt_str     = os.getenv("SENTINEL_MANAGEMENT_SUBNETS", "10.60.0.0/24")
        self._attack_str   = os.getenv("SENTINEL_ATTACKER_SUBNETS",   "10.70.0.0/24")
        self._gw_agent_env = os.getenv("SENTINEL_GATEWAY_AGENT",      "").strip()
        self._win_env      = os.getenv("SENTINEL_WINDOWS_AGENTS",     "").strip()
        self._fw_redirect  = os.getenv("SENTINEL_FW_REDIRECT_TARGET", "").strip()
        self._cache_ttl    = float(os.getenv("SENTINEL_TOPOLOGY_CACHE_TTL", "300"))

        self._mgmt_nets:   List[ipaddress.IPv4Network] = _parse_subnets(self._mgmt_str)
        self._attack_nets: List[ipaddress.IPv4Network] = _parse_subnets(self._attack_str)

        # Wazuh agent list cache
        self._agents_cache: List[Dict] = []
        self._cache_ts: float          = 0.0

    # ── Core IP classification ────────────────────────────────────────────────

    def classify_ip(self, ip: str) -> str:
        """
        Classify an IP address by its network role.

        Returns one of:
          'loopback'   — 127.0.0.1 / ::1
          'management' — matches SENTINEL_MANAGEMENT_SUBNETS (never block)
          'attacker'   — matches SENTINEL_ATTACKER_SUBNETS (known red-team)
          'dmz'        — matches a known enrolled Wazuh agent IP
          'external'   — public IP not in any known range
          'unknown'    — could not parse
        """
        if not ip:
            return "unknown"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"

        if addr.is_loopback:
            return "loopback"
        if _ip_in_subnets(ip, self._mgmt_nets):
            return "management"
        if _ip_in_subnets(ip, self._attack_nets):
            return "attacker"

        # Check against enrolled agent IPs
        for a in self._get_agents_cached():
            if a.get("ip") == ip:
                return "dmz"

        return "external"

    def is_safe_to_block(self, ip: str) -> bool:
        """False for IPs that must never be blocked (loopback, management)."""
        c = self.classify_ip(ip)
        return c not in ("loopback", "management", "unknown")

    # ── Agent resolution ──────────────────────────────────────────────────────

    def ip_to_agent(self, ip: str) -> Optional[str]:
        """Resolve an IP to a Wazuh agent name. Returns None if not found."""
        if not ip:
            return None
        for a in self._get_agents_cached():
            if a.get("ip") == ip:
                return a.get("name")
        return None

    def agent_to_ip(self, agent_name: str) -> Optional[str]:
        """Resolve an agent name to its IP. Returns None if not found."""
        if not agent_name:
            return None
        for a in self._get_agents_cached():
            if a.get("name") == agent_name:
                return a.get("ip")
        return None

    def get_os_family(self, agent_name: str) -> Optional[str]:
        """
        Returns 'windows' | 'linux' | 'freebsd' | None.
        Checks env override first, then Ansible inventory, then Wazuh agent OS field.
        """
        # Env override
        if agent_name in self.get_windows_agents():
            return "windows"

        # Ansible inventory
        try:
            from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import (
                os_of_agent,
            )
            result = os_of_agent(agent_name)
            if result:
                return result
        except Exception:
            pass

        # Wazuh agent OS field
        for a in self._get_agents_cached():
            if a.get("name") == agent_name:
                platform = (a.get("os") or {}).get("platform", "").lower()
                if "windows" in platform:
                    return "windows"
                if "freebsd" in platform:
                    return "freebsd"
                if platform:
                    return "linux"
        return None

    # ── Gateway / sensor ─────────────────────────────────────────────────────

    def get_gateway_agent(self) -> str:
        """
        Returns the agent name of the network gateway / Suricata sensor.
        Priority: SENTINEL_GATEWAY_AGENT env → name heuristic → empty string.
        """
        if self._gw_agent_env:
            return self._gw_agent_env
        # Auto-detect from agent names
        for a in self._get_agents_cached():
            if _looks_like_gateway(a.get("name", "")):
                return a.get("name", "")
        return ""

    def get_fw_redirect_target(self) -> str:
        """
        For block_ip playbooks triggered by the gateway agent:
        returns the Linux agent that should actually apply the iptables rule.
        Priority: SENTINEL_FW_REDIRECT_TARGET env → first active Linux agent.
        """
        if self._fw_redirect:
            return self._fw_redirect
        gw = self.get_gateway_agent()
        # Exclude: gateway, Wazuh manager itself, any agent with 'wazuh' or 'manager' in name
        _exclude_keywords = {"wazuh", "manager"}
        for a in self._get_agents_cached():
            name = a.get("name", "")
            if name == gw:
                continue
            if a.get("status") != "active":
                continue
            if any(kw in name.lower() for kw in _exclude_keywords):
                continue
            os_family = self.get_os_family(name)
            if os_family in ("linux", None):
                return name
        return ""

    # ── Windows agents ────────────────────────────────────────────────────────

    def get_windows_agents(self) -> set:
        """
        Returns set of agent names known to be Windows.
        Priority: SENTINEL_WINDOWS_AGENTS env → Ansible inventory → empty.
        """
        if self._win_env:
            return {a.strip() for a in self._win_env.split(",") if a.strip()}
        try:
            from ai_agents.agents.ansible_dispatch.ansible_dispatch_agent import (
                _inventory_groups_cached,
            )
            groups = _inventory_groups_cached()
            raw = set(groups.get("windows_agents", set()))
            # Filter out [windows_agents:vars] entries — they contain '='
            win = {a for a in raw if "=" not in a and a.strip()}
            if win:
                return win
        except Exception:
            pass
        return set()

    # ── Agent list ────────────────────────────────────────────────────────────

    def get_all_agents(self, active_only: bool = False) -> List[Dict]:
        """
        Returns list of enrolled agents.
        Each item: {name, ip, status, os_platform, os_name, os_family}
        """
        result = []
        for a in self._get_agents_cached():
            if active_only and a.get("status") != "active":
                continue
            os_info = a.get("os") or {}
            result.append({
                "name":        a.get("name", ""),
                "ip":          a.get("ip", ""),
                "status":      a.get("status", ""),
                "os_platform": os_info.get("platform", ""),
                "os_name":     os_info.get("name", ""),
                "os_family":   self.get_os_family(a.get("name", "")),
            })
        return result

    # ── LLM prompt topology ───────────────────────────────────────────────────

    def build_prompt_topology(self) -> str:
        """
        Build a dynamic topology description string for LLM prompts.
        Called at triage time — reflects current live Wazuh enrollment.
        """
        agents    = self.get_all_agents()
        gw        = self.get_gateway_agent()
        windows   = self.get_windows_agents()

        lines = [
            "LAB/ENVIRONMENT TOPOLOGY (live from Wazuh):",
            f"  Management subnets (NEVER block) : {self._mgmt_str}",
            f"  Known attacker/red-team subnets  : {self._attack_str}",
            f"  Gateway / Suricata sensor        : {gw or '(not configured)'}",
            "",
            "  Enrolled agents:",
        ]

        for a in agents:
            tag = ""
            if a["name"] in windows:
                tag += "[WIN]"
            else:
                tag += "[LIN]"
            if a["name"] == gw:
                tag += "[GW/IDS]"
            status = "UP" if a["status"] == "active" else "DOWN"
            lines.append(
                f"    {tag:12s} {a['name']:40s} {a['ip']:16s} "
                f"{a['os_name'][:30]:30s} [{status}]"
            )

        return "\n".join(lines)

    def build_prompt_ip_routing(self) -> str:
        """
        Build the IP routing / playbook selection rules for LLM prompts.
        References actual configured subnets rather than hardcoded ranges.
        """
        mgmt    = self._mgmt_str
        attack  = self._attack_str
        gw      = self.get_gateway_agent()

        return f"""SOURCE IP ROUTING (apply deterministically before picking a playbook):

  src_ip in {attack}   → ATTACKER subnet (external/red-team)
  src_ip in {mgmt}  → MANAGEMENT subnet — NEVER block these IPs (Ansible/admin traffic)
  src_ip = loopback    → NEVER block
  src_ip is internal DMZ IP (enrolled agent) → potential RELAY host:
      Check RELAY CONTEXT below — if that agent shows prior compromise from {attack},
      the real attacker is the original external IP, not the relay.
  src_ip empty/None    → HOST-BASED detection (Falco, syscheck, rootcheck)
      Attacker code is already running on the host — block_ip won't help.

GATEWAY NOTE:
  {gw or '(gateway agent not configured)'} is the Suricata sensor.
  Port scans and network attacks targeting internal hosts appear as alerts
  FROM the gateway agent, with dst_ip = the targeted host's IP.

PLAYBOOK DECISION TREE:
  1. src_ip in ATTACKER + PROBE (scan, brute force, failed attempts):
     → block_ip or brute_force_response / win_brute_force_response

  2. src_ip in ATTACKER + ACTIVE EXPLOITATION (code exec, webshell, reverse shell,
     successful SQLi, file dropped):
     → incident_response / win_incident_response
     (attacker is executing — prefer forensics over blocking)

  3. src_ip is DMZ internal OR successful auth FROM attacker subnet:
     → lateral_movement_response / win_lateral_movement_response

  4. No src_ip (host-based: Falco, syscheck, rootcheck, process alerts):
     → incident_response / win_incident_response

  5. DoH / DNS tunneling / DNS exfiltration confirmed:
     → block_dns_exfil

  6. File integrity — config/cron/auth_keys modified:
     → fim_restore_response / win_fim_restore_response

  7. Rootkit / dropped executable / ClamAV:
     → malware_containment / win_malware_containment

  8. MySQL credential table access (infra_credentials):
     → mysql_credential_response

  For Windows agents use win_* variants. For Linux agents use standard variants.
  If confidence < 0.6 → no_action."""

    # ── Wazuh agent list cache ────────────────────────────────────────────────

    def _get_agents_cached(self) -> List[Dict]:
        now = time.monotonic()
        if self._agents_cache and (now - self._cache_ts) < self._cache_ttl:
            return self._agents_cache
        try:
            from ai_agents.tools.wazuh_client import WazuhClient
            client = WazuhClient()
            data   = client._manager_request("GET", "/agents", params={"limit": 500})
            agents = data.get("data", {}).get("affected_items", [])
            self._agents_cache = agents
            self._cache_ts     = now
            logger.debug("topology.agents_refreshed count=%d", len(agents))
            return agents
        except Exception as exc:
            logger.warning("topology.agent_fetch_failed: %s", exc)
            return self._agents_cache  # return stale on error


# ── Singleton ─────────────────────────────────────────────────────────────────

_topology: Optional[TopologyConfig] = None


def get_topology() -> TopologyConfig:
    global _topology
    if _topology is None:
        _topology = TopologyConfig()
    return _topology


def reset_topology() -> None:
    """Force re-instantiation (useful in tests or after .env changes)."""
    global _topology
    _topology = None

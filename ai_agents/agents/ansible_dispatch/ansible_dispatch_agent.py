"""
Hybrid Ansible Dispatcher — static rule map + LLM fallback + safety gates.

Routing priority:
  1. Static map (rule_id → playbook) — fast, deterministic
  2. Group-based heuristics (e.g., "suricata" + "scan" → lateral_movement)
  3. LLM fallback — for novel alerts

Safety gates:
  - dry_run for rule_level < 7
  - manual approval for rule_level 7-9 (logs intent, doesn't execute)
  - auto-execute for rule_level >= 10 AND confidence >= threshold
"""
import json
import os
import re
import time
from pathlib import Path
import dspy
import structlog
from ai_agents.agents.base_agent import BaseAgent
from ai_agents.integrations.wazuh_feedback import (
    feedback_received, feedback_decision, feedback_dry_run,
    feedback_executed, feedback_failed, feedback_no_action,
)
from ai_agents.dspy_modules.signatures import ResponseDecision
from ai_agents.tools.ansible_trigger import AnsibleTrigger
from ai_agents.config import get_settings
from ai_agents.llm.fallback import get_lm

logger = structlog.get_logger()

# ── Static rule → playbook map ─────────────────────────────────────────
# Wazuh rule IDs: https://documentation.wazuh.com/current/user-manual/ruleset/rules-classification.html
STATIC_RULE_MAP = {
    # ─── DoH 4-layer exfiltration (Phase 2A) ──────────────────────────
    "100423": {"playbook": "block_dns_exfil", "severity": "high"},
    "100424": {"playbook": "block_dns_exfil", "severity": "critical"},
    # ─── AD-CS ESC1 abuse (Phase 2B) ──────────────────────────────────────
    "100534": {"playbook": "block_adcs_abuse", "severity": "critical"},
    "100601": {"playbook": "harden_nginx_tls", "severity": "high"},
    "100611": {"playbook": "mysql_credential_response", "severity": "critical"},
    "100612": {"playbook": "mysql_credential_response", "severity": "critical"},
    "100602": {"playbook": "harden_nginx_tls", "severity": "high"},
    "100536": {"playbook": "block_adcs_abuse", "severity": "critical"},
    "100540": {"playbook": "block_adcs_abuse", "severity": "critical"},
    # ─── SSH brute force (Linux) ──────────────────────────────────────
    "5712": {"playbook": "brute_force_response", "severity": "high"},
    "5710": {"playbook": "brute_force_response", "severity": "high"},
    "5720": {"playbook": "brute_force_response", "severity": "high"},
    "100006": {"playbook": "brute_force_response", "severity": "high"},

    # ─── Windows authentication & RDP brute force ─────────────────────
    "60122": {"playbook": "win_brute_force_response", "severity": "high"},
    "60204": {"playbook": "win_brute_force_response", "severity": "high"},
    "60111": {"playbook": "win_compromised_user_response", "severity": "high"},
    "60112": {"playbook": "win_compromised_user_response", "severity": "high"},

    # ─── Web attacks (cross-platform; OS-routed) ──────────────────────
    "31103": {"playbook": "incident_response", "severity": "high",
              "os_variants": {"windows": "win_incident_response"}},
    "31104": {"playbook": "incident_response", "severity": "high",
              "os_variants": {"windows": "win_incident_response"}},
    "31108": {"playbook": "incident_response", "severity": "high",
              "os_variants": {"windows": "win_incident_response"}},
    "31516": {"playbook": "incident_response", "severity": "medium",
              "os_variants": {"windows": "win_incident_response"}},

    # ─── FIM events (OS-routed) ───────────────────────────────────────
    "550": {"playbook": "fim_restore_response", "severity": "medium",
            "os_variants": {"windows": "win_fim_restore_response"}},
    "553": {"playbook": "fim_restore_response", "severity": "medium",
            "os_variants": {"windows": "win_fim_restore_response"}},
    "554": {"playbook": "file_quarantine_response", "severity": "high",
            "os_variants": {"windows": "win_file_quarantine"}},
    "594": {"playbook": "fim_restore_response", "severity": "medium",
            "os_variants": {"windows": "win_fim_restore_response"}},

    # ─── Rootkit / malware detection (Linux) ──────────────────────────
    "510": {"playbook": "malware_containment", "severity": "critical"},
    "511": {"playbook": "malware_containment", "severity": "critical"},

    # ─── Sysmon / Defender events (Windows malware) ───────────────────
    "61603": {"playbook": "win_malware_containment", "severity": "high"},
    "61605": {"playbook": "win_malware_containment", "severity": "high"},
    "61612": {"playbook": "win_malware_containment", "severity": "high"},
    "62106": {"playbook": "win_malware_containment", "severity": "critical"},
    "62108": {"playbook": "win_malware_containment", "severity": "critical"},
    "92213": {"playbook": "win_malware_containment", "severity": "high"},
    "92301": {"playbook": "win_malware_containment", "severity": "high"},

    # ─── Privilege escalation / account compromise (Linux) ────────────
    "40111": {"playbook": "compromised_user_response", "severity": "critical"},
    "5402": {"playbook": "compromised_user_response", "severity": "high"},
    "5403": {"playbook": "compromised_user_response", "severity": "high"},

    # ─── Permissions tampering (OS-routed) ────────────────────────────
    "5901": {"playbook": "permissions_restore_response", "severity": "medium",
             "os_variants": {"windows": "win_permissions_restore_response"}},

    # ─── Port scans / recon (OS-routed) ───────────────────────────────
    "40503": {"playbook": "block_ip", "severity": "high"},
    "86601": {"playbook": "block_ip", "severity": "high"},
    "87702": {"playbook": "block_ip", "severity": "high"},
    # Lateral movement — successful remote NTLM logon from external
    "92657": {"playbook": "lateral_movement_response", "severity": "high",
              "os_variants": {"windows": "win_lateral_movement_response"}},
    "100620": {"playbook": "win_lateral_movement_response", "severity": "critical"},
    # Falco: webshell/suspicious process on Linux (shadow read, sensitive file access)
    "100114": {"playbook": "incident_response", "severity": "high"},
    # PowerShell suspicious execution on DC
    "92057": {"playbook": "win_incident_response", "severity": "critical"},

    # ── SSH Brute Force (extended) ──────────────────────────────────
    "5503": {"playbook": "brute_force_response", "severity": "high"},    # SSH max auth attempts exceeded
    "5551": {"playbook": "brute_force_response", "severity": "high"},    # SSH brute force (new variant)
    "5763": {"playbook": "brute_force_response", "severity": "high"},    # SSH scanner detected
    "2502": {"playbook": "brute_force_response", "severity": "medium"},  # FTP brute force
    "2503": {"playbook": "brute_force_response", "severity": "medium"},  # FTP auth failure frequency
    "11325": {"playbook": "brute_force_response", "severity": "high"},   # MySQL brute force
    "30304": {"playbook": "brute_force_response", "severity": "high"},   # Web brute force (DVWA)

    # ── Web Application Attacks ─────────────────────────────────────
    "31103": {"playbook": "incident_response", "severity": "high"},      # SQL injection attempt
    "31104": {"playbook": "incident_response", "severity": "high"},      # XSS attack
    "31108": {"playbook": "incident_response", "severity": "high"},      # Command injection
    "31151": {"playbook": "incident_response", "severity": "high"},      # PHP remote include
    "31516": {"playbook": "incident_response", "severity": "medium"},    # Directory traversal
    "31530": {"playbook": "incident_response", "severity": "critical"},  # Web shell upload
    "31531": {"playbook": "incident_response", "severity": "critical"},  # Web shell execution
    "77101": {"playbook": "incident_response", "severity": "critical"},  # Shellshock / bash injection

    # ── Privilege Escalation ────────────────────────────────────────
    "5402": {"playbook": "compromised_user_response", "severity": "high"},    # sudo -s (root shell obtained)
    "5403": {"playbook": "compromised_user_response", "severity": "high"},    # sudo to root
    "5404": {"playbook": "compromised_user_response", "severity": "critical"},# sudo fail then success
    "40111": {"playbook": "compromised_user_response", "severity": "critical"},# Privilege escalation

    # ── Malware / Rootkit (Wazuh built-in) ─────────────────────────
    "510": {"playbook": "malware_containment", "severity": "critical"},  # Rootkit hidden file
    "511": {"playbook": "malware_containment", "severity": "critical"},  # Rootkit hidden process
    "533": {"playbook": "malware_containment", "severity": "critical"},  # Worm detected
    "9502": {"playbook": "malware_containment", "severity": "critical"}, # ClamAV: virus found
    "9503": {"playbook": "malware_containment", "severity": "critical"}, # ClamAV: virus moved

    # ── Act 3: AS-REP Roast / Kerberoast (custom rules 100700+) ────
    "100700": {"playbook": "incident_response", "severity": "high"},     # AS-REP roast attempt
    "100701": {"playbook": "incident_response", "severity": "critical"}, # AS-REP roast frequency
    "100710": {"playbook": "incident_response", "severity": "high"},     # Kerberoast SPN enumeration
    "100711": {"playbook": "incident_response", "severity": "critical"}, # Kerberoast TGS-REQ spike

    # ── Act 3: SSH Lateral Movement ─────────────────────────────────
    "5715": {"playbook": "block_ip", "severity": "high"},                # SSH login from Kali IP
    "100720": {"playbook": "block_ip", "severity": "critical"},          # SSH lateral from attacker

    # ── Act 3: Raw TCP / NC Exfiltration ────────────────────────────
    "100730": {"playbook": "block_ip", "severity": "critical"},          # Raw TCP exfil to external
    "100731": {"playbook": "block_dns_exfil", "severity": "critical"},   # Data staging detected

    # ── Windows-specific Attacks ────────────────────────────────────
    "60106": {"playbook": "win_incident_response", "severity": "high"},        # Account lockout
    "60122": {"playbook": "win_incident_response", "severity": "high"},        # Failed logon frequency
    "91545": {"playbook": "win_incident_response", "severity": "critical"},    # Mimikatz detected
    "91556": {"playbook": "win_incident_response", "severity": "critical"},    # Rubeus/Kerberoast tool
    "92200": {"playbook": "win_incident_response", "severity": "critical"},    # LSASS access non-system
    "92656": {"playbook": "win_lateral_movement_response", "severity": "critical"}, # Pass-the-Hash

    # ── Network-level Suricata (extended) ───────────────────────────
    "40116": {"playbook": "block_ip", "severity": "medium"},  # ET SCAN: Nessus scan
    "40117": {"playbook": "block_ip", "severity": "medium"},  # ET SCAN: OpenVAS scan
    "86001": {"playbook": "block_ip", "severity": "high"},    # Suricata: SSH brute force
    "86002": {"playbook": "block_ip", "severity": "high"},    # Suricata: FTP brute force

    # ── DoH Exfil (full chain) ──────────────────────────────────────
    "100420": {"playbook": "block_dns_exfil", "severity": "high"},     # DoH exfil stage 2
    "100421": {"playbook": "block_dns_exfil", "severity": "high"},     # DoH exfil stage 3
    "100423": {"playbook": "block_dns_exfil", "severity": "critical"}, # DoH exfil confirmed
    "100750": {"playbook": "block_dns_exfil", "severity": "high"},    # DoH iptables LOG detection
    "100751": {"playbook": "block_dns_exfil", "severity": "critical"}, # DoH exfil campaign

    # ── Persistence (extended) ──────────────────────────────────────
    "553": {"playbook": "fim_restore_response", "severity": "high"},   # File deleted from monitored dir
    "100740": {"playbook": "incident_response", "severity": "critical"}, # Ransom note dropped via webshell
    "100301": {"playbook": "fim_restore_response", "severity": "critical"}, # SSH authorized_keys modified
    "100302": {"playbook": "fim_restore_response", "severity": "high"},     # Crontab modified

    # ─── Windows security log tampering / lateral movement ────────────
    "18152": {"playbook": "win_incident_response", "severity": "critical"},
    "60103": {"playbook": "win_lateral_movement_response", "severity": "high"},
    "60157": {"playbook": "win_lateral_movement_response", "severity": "high"},
}

# ── Group-based heuristics ────────────────────────────────────────────
# If rule_id isn't in static map, inspect rule.groups for keywords
GROUP_HEURISTICS = [
    (["suricata", "scan"], "lateral_movement_response", "medium"),
    (["suricata", "attack"], "incident_response", "high"),
    (["suricata", "trojan"], "malware_containment", "critical"),
    (["authentication_failed"], "brute_force_response", "high"),
    (["web_attack"], "incident_response", "high"),
    (["rootcheck"], "malware_containment", "critical"),
    (["rootkit"], "malware_containment", "critical"),
    (["syscheck"], "fim_restore_response", "medium"),
]


# ── Playbook ↔ OS compatibility ────────────────────────────────────────
# Declares which OS family each playbook supports. The dispatcher uses
# this to skip incompatible (playbook, target_agent) pairs BEFORE
# calling the Ansible runner — prevents "powershell shell family is
# incompatible with sudo" 500s and similar.
PLAYBOOK_OS = {
    # ─── Linux playbooks (iptables, sudo, systemctl) ──────────────────
    "brute_force_response":         {"linux"},
    "block_dns_exfil":              {"linux"},
    "incident_response":            {"linux"},
    "malware_containment":          {"linux"},
    "lateral_movement_response":    {"linux", "windows"},
    "vulnerability_patch":          {"linux"},
    "file_quarantine_response":     {"linux"},
    "compromised_user_response":    {"linux"},
    "permissions_restore_response": {"linux"},
    "fim_restore_response":         {"linux"},

    # ─── Windows playbooks (WinRM, PowerShell, Windows Firewall) ──────
    "win_brute_force_response":         {"windows"},
    "win_incident_response":            {"windows"},
    "win_malware_containment":          {"windows"},
    "win_lateral_movement_response":    {"windows"},
    "win_vulnerability_patch":          {"windows"},
    "win_file_quarantine":              {"windows"},
    "win_compromised_user_response":    {"windows"},
    "win_permissions_restore_response": {"windows"},
    "win_fim_restore_response":         {"windows"},
    "block_adcs_abuse":                 {"windows"},
    "harden_nginx_tls":                 {"linux"},
    "mysql_credential_response":        {"linux"},
    "block_ip":                         {"linux", "windows", "unknown"},
    "block_dns_exfil":                  {"linux"},
}


# ── Live-inventory awareness ───────────────────────────────────────────
# We look at the inventory file (auto-regenerated every 60s by the
# in-container watcher daemon) to know each agent's OS family and
# reachability. No hardcoded IPs or OS names anywhere; everything
# follows what Wazuh currently reports.

_INVENTORY_FILE = os.getenv("ANSIBLE_INVENTORY_PATH", "/ansible/inventory/hosts.ini")
_INV_CACHE_TTL_S = 10
_inv_cache: dict = {"ts": 0.0, "groups": {}}


def _read_inventory_groups() -> dict:
    """Parse the live hosts.ini into {group_name: {hostname, ...}}.
    Returns {} if the file is missing or unreadable."""
    groups: dict = {}
    current = None
    path = Path(_INVENTORY_FILE)
    if not path.exists():
        return groups
    try:
        for raw in path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^\[([^\]:]+)(?::children|:vars)?\]$", line)
            if m:
                current = m.group(1)
                groups.setdefault(current, set())
                continue
            if current and not line.startswith("ansible_"):
                hostname = line.split()[0]
                groups[current].add(hostname)
    except OSError:
        pass
    return groups


def _inventory_groups_cached() -> dict:
    """Tiny TTL cache so a burst of alerts doesn't re-parse the file 100x."""
    now = time.time()
    if now - _inv_cache["ts"] > _INV_CACHE_TTL_S:
        _inv_cache["groups"] = _read_inventory_groups()
        _inv_cache["ts"] = now
    return _inv_cache["groups"]


def os_of_agent(agent_name: str) -> str | None:
    """Return 'linux' / 'windows' / 'freebsd' / None for a Wazuh agent name.
    Looked up from the live Ansible inventory. None means the agent is
    not in any active OS group (offline, unknown, or not enrolled)."""
    if not agent_name:
        return None
    g = _inventory_groups_cached()
    if agent_name in g.get("linux_agents", set()):
        return "linux"
    if agent_name in g.get("windows_agents", set()):
        return "windows"
    if agent_name in g.get("freebsd_agents", set()):
        return "freebsd"
    return None


def is_reachable(agent_name: str) -> bool:
    """True iff the agent is in an active OS group (not [unreachable])."""
    return os_of_agent(agent_name) is not None


def _resolve_os_variant(decision: dict, agent_name: str) -> dict:
    """If the entry has os_variants and the agent's OS matches, swap in
    the variant playbook name. Otherwise return the decision unchanged."""
    variants = decision.get("os_variants") or {}
    if not variants:
        return decision
    target_os = os_of_agent(agent_name) if agent_name else None
    if target_os and target_os in variants:
        out = {**decision, "playbook": variants[target_os]}
        out.pop("os_variants", None)
        return out
    return decision


def route_alert(alert: dict) -> dict:
    """
    Decide which playbook to run based on alert metadata.
    Returns: {source, playbook, severity, confidence} or None.
    """
    rule = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)
    rule_groups = rule.get("groups", [])

    # 1. Static rule map
    if rule_id in STATIC_RULE_MAP:
        entry = STATIC_RULE_MAP[rule_id]
        decision = {
            "source": "static_map",
            "playbook": entry["playbook"],
            "severity": entry["severity"],
            "confidence": 0.95,
            "rule_id": rule_id,
            "os_variants": entry.get("os_variants"),
        }
        return _resolve_os_variant(
            decision,
            (alert.get("agent") or {}).get("name") or "",
        )

    # 2. Group heuristics
    # OS-variant map for heuristic-routed playbooks. Mirrors the
    # static-map's os_variants pattern so Windows hosts get the win_*
    # variant even when no specific rule_id matched.
    _HEURISTIC_OS_VARIANTS = {
        "fim_restore_response":         {"windows": "win_fim_restore_response"},
        "file_quarantine_response":     {"windows": "win_file_quarantine"},
        "incident_response":            {"windows": "win_incident_response"},
        "malware_containment":          {"windows": "win_malware_containment"},
        "lateral_movement_response":    {"windows": "win_lateral_movement_response"},
        "brute_force_response":         {"windows": "win_brute_force_response"},
        "compromised_user_response":    {"windows": "win_compromised_user_response"},
        "permissions_restore_response": {"windows": "win_permissions_restore_response"},
        "vulnerability_patch":          {"windows": "win_vulnerability_patch"},
    }

    groups_set = set(g.lower() for g in rule_groups)
    for required_groups, playbook, severity in GROUP_HEURISTICS:
        if all(rg in groups_set for rg in required_groups):
            decision = {
                "source": "group_heuristic",
                "playbook": playbook,
                "severity": severity,
                "confidence": 0.75,
                "rule_id": rule_id,
                "matched_groups": required_groups,
                "os_variants": _HEURISTIC_OS_VARIANTS.get(playbook),
            }
            return _resolve_os_variant(
                decision,
                (alert.get("agent") or {}).get("name") or "",
            )

    # 3. No match — caller should fall back to LLM
    return None


def extract_vars_from_alert(alert: dict) -> dict:
    """Extract common playbook vars from alert data.

    Pulls fields from multiple Wazuh shapes:
      - data.srcip / data.dstip / data.srcuser           (generic)
      - syscheck.path                                     (FIM)
      - data.win.eventdata.{Image,ProcessId,CommandLine,TargetFilename}  (Sysmon/Windows)
    """
    data = alert.get("data", {}) or {}
    syscheck = alert.get("syscheck", {}) or {}
    win_eventdata = ((data.get("win") or {}).get("eventdata") or {}) if isinstance(data, dict) else {}

    # Windows process info from Sysmon: Image path -> exe path; ProcessId -> PID
    win_image = win_eventdata.get("Image", "") or win_eventdata.get("image", "")
    win_pid = win_eventdata.get("ProcessId", "") or win_eventdata.get("processId", "")
    win_cmdline = win_eventdata.get("CommandLine", "") or win_eventdata.get("commandLine", "")
    win_target_file = win_eventdata.get("TargetFilename", "") or win_eventdata.get("targetFilename", "")

    # Derive malware_process (just the exe name, no path) for win_malware_containment
    malware_process = ""
    if win_image:
        # e.g. "C:\Windows\System32\powershell.exe" -> "powershell.exe"
        malware_process = win_image.replace("\\", "/").split("/")[-1]

    # AD-CS ESC1 fields (rules 100534/100536/100540). The CA audit event
    # carries the template in win.eventdata.attributes
    # ("CertificateTemplate:NAME SAN:upn=..."), requester, and requestId.
    adcs_attributes = win_eventdata.get("attributes", "") or ""
    adcs_template = ""
    m = re.search(r"CertificateTemplate:([^\s]+)", adcs_attributes)
    if m:
        adcs_template = m.group(1)
    adcs_requester = win_eventdata.get("requester", "") or ""
    adcs_request_id = win_eventdata.get("requestId", "") or win_eventdata.get("requestid", "") or ""

    # For SENTINEL_AI_DOH alerts, source IP is in full_log as "src=10.x.x.x"
    import re as _re
    full_log = alert.get("full_log", "")
    doh_src = ""
    if "SENTINEL_AI_DOH" in full_log or "SENTINEL_DOH" in full_log:
        m = _re.search(r"src=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", full_log)
        if m:
            doh_src = m.group(1)

    return {
        "source_ip":      (doh_src or
                          data.get("srcip") or data.get("src_ip") or
                          win_eventdata.get("ipAddress") or
                          win_eventdata.get("ipaddress", "")),
        "dest_ip":        data.get("dstip") or data.get("dest_ip", ""),
        "username":       data.get("srcuser") or data.get("username", ""),
        "file_path":      syscheck.get("path", "") or win_target_file or "",
        "target_hosts":   (alert.get("agent") or {}).get("name", "all"),
        # Windows malware containment vars:
        "malware_process": malware_process,
        "malware_pid":     str(win_pid) if win_pid else "",
        "malware_cmdline": win_cmdline,
        # AD-CS ESC1 containment vars:
        "template_name":   adcs_template,
        "requester":       adcs_requester,
        "request_id":      str(adcs_request_id) if adcs_request_id else "",
    }


class HybridAnsibleDispatcher(BaseAgent):
    """Hybrid dispatcher — static routing first, LLM fallback."""
    name = "ansible_dispatch"

    def __init__(self):
        super().__init__()
        s = get_settings()
        self._decide = dspy.ChainOfThought(ResponseDecision)
        self._trigger = AnsibleTrigger()
        self._threshold = s.ansible_confidence_threshold

        # Safety thresholds
        self._auto_execute_level = int(os.getenv("ANSIBLE_AUTO_EXECUTE_LEVEL", "10"))
        self._dry_run_below_level = int(os.getenv("ANSIBLE_DRY_RUN_BELOW_LEVEL", "7"))

    async def run(self, input_data: dict) -> dict:
        alert = input_data.get("alert", {})
        analysis = input_data.get("analysis", "")
        incident_id = input_data.get("incident_id", "unknown")

        rule_level = alert.get("rule", {}).get("level", 0)
        rule_id = str(alert.get("rule", {}).get("id", ""))
        agent_name_early = (alert.get("agent") or {}).get("name") or ""

        # Emit dispatch_received so the chain is visible even if blocked downstream
        try:
            from ai_agents.integrations.wazuh_feedback import feedback_received
            feedback_received(
                incident_id=incident_id, rule_id=rule_id,
                level=rule_level, agent=agent_name_early,
            )
        except Exception:
            pass

        # Step 1: Try static routing
        decision = route_alert(alert)
        decision_source = decision["source"] if decision else None

        # Step 2: LLM fallback
        if not decision:
            self.logger.info("dispatch.llm_fallback", rule_id=rule_id)
            try:
                lm = get_lm(preferred="cerebras")
                with dspy.context(lm=lm):
                    llm_decision = self._decide(
                        threat_analysis=analysis,
                        alert_type=input_data.get("alert_type", "other"),
                        severity=input_data.get("severity", "medium"),
                        confidence=str(input_data.get("confidence", 0.5)),
                    )
                if llm_decision.should_respond.strip().lower() == "yes":
                    decision = {
                        "source": "llm",
                        "playbook": llm_decision.playbook,
                        "severity": input_data.get("severity", "medium"),
                        "confidence": float(input_data.get("confidence", 0.5)),
                        "rule_id": rule_id,
                        "reasoning": llm_decision.reasoning,
                    }
                    decision_source = "llm"
                else:
                    return {"executed": False, "reason": f"LLM declined: {llm_decision.reasoning}", "playbook": None}
            except Exception as e:
                self.logger.warning("dispatch.llm_failed", error=str(e))
                return {"executed": False, "reason": f"LLM dispatch failed: {e}", "playbook": None}

        # Step 2.5: OS / reachability gate
        # Before doing anything else, make sure the target agent is
        # (a) reachable in the current inventory, and
        # (b) running an OS the chosen playbook actually supports.
        agent_name = (alert.get("agent") or {}).get("name") or ""
        # Reroute pfSense block_ip to a Linux host (pfSense is FreeBSD/unknown)
        if decision.get("playbook") == "block_ip" and "sentinel-fw" in agent_name:
            agent_name = "Ubuntu-agent-web"
        target_os = os_of_agent(agent_name)
        if target_os is None:
            self.logger.info(
                "dispatch.skip_unreachable",
                agent=agent_name, rule_id=rule_id,
                playbook=decision["playbook"],
            )
            feedback_no_action(
                incident_id=incident_id, rule_id=rule_id, agent=agent_name,
                reason="target_unreachable",
            )
            return {
                "executed": False,
                "reason": f"agent {agent_name!r} is not in active inventory "
                          f"groups (offline / unknown / not enrolled)",
                "playbook": decision["playbook"],
                "skip_kind": "target_unreachable",
            }
        allowed_os = PLAYBOOK_OS.get(decision["playbook"], set())
        if allowed_os and target_os not in allowed_os:
            self.logger.info(
                "dispatch.skip_incompatible_os",
                agent=agent_name, target_os=target_os,
                playbook=decision["playbook"],
                playbook_supports=sorted(allowed_os),
                rule_id=rule_id,
            )
            feedback_no_action(
                incident_id=incident_id, rule_id=rule_id, agent=agent_name,
                reason=f"incompatible_os: {decision['playbook']} needs "
                       f"{sorted(allowed_os)}, agent is {target_os}",
            )
            return {
                "executed": False,
                "reason": f"playbook {decision['playbook']!r} supports "
                          f"{sorted(allowed_os)} but agent {agent_name!r} "
                          f"is {target_os}",
                "playbook": decision["playbook"],
                "skip_kind": "incompatible_os",
            }

        # Decision is locked in; tell Wazuh about it
        feedback_decision(
            incident_id=incident_id, rule_id=rule_id, agent=agent_name,
            playbook=decision["playbook"],
            decision_source=decision_source or decision.get("source", "unknown"),
            ai_severity=decision.get("severity", ""),
            confidence=decision.get("confidence", ""),
        )

        # Step 3: Safety gates
        dry_run = False
        if rule_level < self._dry_run_below_level:
            self.logger.info("dispatch.skip_low_severity", rule_level=rule_level)
            return {"executed": False, "reason": f"Rule level {rule_level} below response threshold", "playbook": decision["playbook"]}

        if rule_level < self._auto_execute_level:
            # Medium severity — dry run only
            dry_run = True
            self.logger.info("dispatch.dry_run", rule_level=rule_level, playbook=decision["playbook"])

        if decision.get("confidence", 0) < self._threshold:
            return {"executed": False, "reason": f"Confidence {decision.get('confidence')} below threshold {self._threshold}", "playbook": decision["playbook"]}

        # Step 4: Build playbook vars
        extra_vars = extract_vars_from_alert(alert)
        # For block_ip triggered by pfSense (FreeBSD), redirect to a Linux host
        agent_name = (alert.get("agent") or {}).get("name", "")
        if decision.get("playbook") == "block_ip" and "sentinel-fw" in agent_name:
            extra_vars["target_hosts"] = "Ubuntu-agent-web"
            extra_vars["block_ip_address"] = extra_vars.get("source_ip", "")
        extra_vars.update({
            "incident_id": incident_id,
            "severity": decision["severity"],
            "dry_run": dry_run,
        })
        # AD-CS containment: supply ca_name (single CA in this lab) and
        # ensure template_name is set. The dispatcher pulls template/requester/
        # request_id from the alert in extract_vars_from_alert.
        if decision["playbook"] == "block_adcs_abuse":
            extra_vars.setdefault("ca_name", os.getenv("ADCS_CA_NAME", "SENTINEL-LAB-CA"))
            if not extra_vars.get("template_name"):
                extra_vars["template_name"] = os.getenv("ADCS_TEMPLATE_NAME", "SentinelVulnESC1")

        # Phase 2A: DoH-class alerts carry source IP in non-standard fields.
        # 100401-405 (L3 dnsdist): data.doh_client_ip
        # 100412 (L1 Suricata TLS): data.src_ip (no srcip abbreviation)
        # 100423/424 (correlation): may inherit either
        if not extra_vars.get("source_ip"):
            data = alert.get("data", {}) or {}
            # Try flat fields first (L3 dnsdist decoder, L1 Suricata)
            # Then nested Falco output_fields.fd.cip (L2, also carries through 100422/100423)
            output_fields = data.get("output_fields", {}) or {}
            fd_fields = output_fields.get("fd", {}) or {}
            extra_vars["source_ip"] = (
                data.get("doh_client_ip")
                or data.get("src_ip")
                or data.get("fd_cip")
                or fd_fields.get("cip")
                or ""
            )
        # target_hosts already defaulted to alert.agent.name by extract_vars_from_alert.
        # For DoH playbooks the target IS the DoH server agent, not the attacker.

        # Step 5: Playbook-specific guards — prevent false positive execution
        playbook_name = decision["playbook"]

        # Guard A: Windows IP-based playbooks require a valid non-loopback source IP.
        # Without a real attacker IP the playbook would block nothing or block the wrong host.
        ip_required_playbooks = {
            "win_brute_force_response", "win_compromised_user_response",
            "win_lateral_movement_response", "brute_force_response",
            "lateral_movement_response", "block_dns_exfil",
        }
        if playbook_name in ip_required_playbooks:
            src = extra_vars.get("source_ip", "")
            if not src or src in ("127.0.0.1", "::1", "-", ""):
                self.logger.warning(
                    "dispatch.guard.no_source_ip",
                    playbook=playbook_name, incident_id=incident_id,
                    reason="source_ip empty or loopback — skipping to prevent false positive"
                )
                return {"executed": False, "reason": f"Guard: {playbook_name} requires non-loopback source_ip, got '{src}'", "playbook": playbook_name}

        # Guard B: Windows malware containment requires a real non-system process to kill.
        # Reject empty process AND known-safe system binaries that Ansible/WinRM itself spawns.
        SAFE_SYSTEM_BINARIES = {
            "powershell.exe", "cmd.exe", "wsmprovhost.exe", "csc.exe",
            "conhost.exe", "svchost.exe", "lsass.exe", "services.exe",
            "wininit.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe",
            "spoolsv.exe", "msiexec.exe", "wuauclt.exe", "tiworker.exe",
        }
        if playbook_name in ("win_malware_containment", "malware_containment"):
            proc = extra_vars.get("malware_process", "").lower().strip()
            if not proc:
                self.logger.warning(
                    "dispatch.guard.no_malware_process",
                    playbook=playbook_name, incident_id=incident_id,
                    reason="malware_process empty — skipping to prevent false positive taskkill"
                )
                return {"executed": False, "reason": f"Guard: {playbook_name} requires malware_process, got empty string", "playbook": playbook_name}
            if proc in SAFE_SYSTEM_BINARIES:
                self.logger.warning(
                    "dispatch.guard.safe_binary",
                    playbook=playbook_name, incident_id=incident_id,
                    process=proc,
                    reason=f"malware_process '{proc}' is a known-safe system binary — skipping to prevent false positive"
                )
                return {"executed": False, "reason": f"Guard: malware_process '{proc}' is a system binary, not malware", "playbook": playbook_name}

        # Guard C: Destructive playbooks must never target 'all' hosts.
        # 'all' means inventory-wide — would contain every agent simultaneously.
        DESTRUCTIVE_PLAYBOOKS = {
            "win_malware_containment", "malware_containment",
            "win_brute_force_response", "brute_force_response",
            "win_compromised_user_response", "compromised_user_response",
            "isolate_host", "win_lateral_movement_response", "lateral_movement_response",
            "block_dns_exfil", "block_adcs_abuse",
        }
        if playbook_name in DESTRUCTIVE_PLAYBOOKS:
            hosts = extra_vars.get("target_hosts", "all")
            if hosts in ("all", "", None):
                agent_name = (alert.get("agent") or {}).get("name", "")
                if agent_name:
                    extra_vars["target_hosts"] = agent_name
                    self.logger.info(
                        "dispatch.guard.narrowed_target",
                        playbook=playbook_name, from_hosts="all", to_host=agent_name
                    )
                else:
                    self.logger.warning(
                        "dispatch.guard.no_target",
                        playbook=playbook_name, incident_id=incident_id,
                        reason="target_hosts=all and no agent name — skipping to prevent mass execution"
                    )
                    return {"executed": False, "reason": f"Guard: {playbook_name} target_hosts=all with no agent name", "playbook": playbook_name}

        # Step 5: Execute
        try:
            result = await self._trigger.run_playbook(
                playbook=decision["playbook"],
                extra_vars=extra_vars,
            )
            if dry_run:
                feedback_dry_run(
                    incident_id=incident_id, rule_id=rule_id, agent=agent_name,
                    playbook=decision["playbook"],
                )
            else:
                stats = (result or {}).get("stats", {}) if isinstance(result, dict) else {}
                feedback_executed(
                    incident_id=incident_id, rule_id=rule_id, agent=agent_name,
                    playbook=decision["playbook"],
                    rc=(result or {}).get("rc", "?") if isinstance(result, dict) else "?",
                    ok=stats.get("ok", 0),
                    changed=stats.get("changed", 0),
                    failed=stats.get("failed", 0),
                )
            return {
                "executed": True,
                "dry_run": dry_run,
                "playbook": decision["playbook"],
                "decision_source": decision_source,
                "extra_vars": extra_vars,
                "rule_id": rule_id,
                "rule_level": rule_level,
                "result": result,
            }
        except Exception as e:
            self.logger.error("dispatch.execution_failed", error=str(e))
            feedback_failed(
                incident_id=incident_id, rule_id=rule_id, agent=agent_name,
                playbook=decision["playbook"], reason=str(e)[:200],
            )
            return {"executed": False, "reason": f"Execution failed: {e}", "playbook": decision["playbook"]}


# Alias to keep the existing import path working
AnsibleDispatchAgent = HybridAnsibleDispatcher

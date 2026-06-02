"""
Subscribe to Redis ALERT_CHANNEL and dispatch every new alert to the
OrchestratorAgent for full triage (classify -> enrich -> CVE map ->
incident -> playbook routing).

Pairs with wazuh_alert_consumer (publisher). Started as a background
asyncio task from main.py.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import structlog

from ai_agents.integrations.redis_manager import get_redis

logger = structlog.get_logger()

ALERT_CHANNEL = "sentinel:alerts"

# Skip alerts below this rule.level — matches consumer's own filter
# (level_gte=5) but we double-check at dispatch time so a future
# consumer change can't accidentally flood the orchestrator.
DISPATCH_MIN_LEVEL = int(os.getenv("DISPATCH_MIN_LEVEL", "5"))

# Per (rule_id, agent_name) dedup window. The same rule firing on the
# same agent within this many seconds will only trigger orchestrator
# once. Defends against burst floods (e.g. nmap scan firing 30
# ET SCAN MSSQL alerts in 5 seconds — orchestrator only needs to see
# one to triage).
DISPATCH_DEDUP_WINDOW_S = float(os.getenv("DISPATCH_DEDUP_WINDOW_S", "60"))

# Set to "1" to bypass the noise filter (e.g. for testing all rules)
DISABLE_NOISE_FILTER = os.getenv("DISPATCH_DISABLE_NOISE_FILTER", "0") == "1"

# Rules with no SOC value on this lab — desktop / dpkg / systemd noise
HARD_SKIP_RULES = {
    40704,   # systemd unit failure (desktop app crashes)
    2902,    # dpkg package installed (workstation noise)
    2904,    # dpkg package removed (workstation noise)
    # SENTINEL-AI feedback rules — would create dispatch loop
    100500, 100501, 100502, 100503, 100504, 100505, 100506, 100507,
    # Windows NTLM logon — too noisy (Ansible WinRM generates constantly)
    # Lateral movement detected via custom rule 100620 instead
    92657,
    # Windows Ansible/WinRM operational noise — zero SOC value
    92213,   # Windows scheduled task created/modified (Ansible artifact)
    62154,   # Windows service state change (Ansible WinRM side effect)
    60010,   # Windows Event Log cleared (harmless in lab)
    91809,   # PowerShell Base64 decode — Ansible uses this constantly
    # Windows MSI / .NET compiler noise
    60910,   # Windows Installer event
    60911,   # Windows Installer completed
    92057,   # PowerShell on DC — constant Ansible WinRM noise
    60702,   # VSS service timeout — Windows background noise
    # Wazuh agent keepalive / inventory events — not threats
    521,     # Wazuh agent started
    502,     # Wazuh agent stopped
    503,     # Wazuh agent disconnected
    92103,   # LDAP from PowerShell (Ansible WinRM LDAP queries — constant noise)
    61102,   # Windows logon/logoff session (Ansible WinRM session events)
    60602,   # Windows account logon (normal auth events from management)
}

# FIM rules that need path-based filtering (real changes still pass)
_FIM_RULES = {550, 553, 554}

# Substring patterns for FIM paths that are KNOWN noise. If a FIM
# alert's syscheck.path contains any of these, skip dispatch.
_FIM_NOISE_PATTERNS = (
    # User desktop / session state
    "/.config/", "/.local/", "/.cache/", "/.xsession-errors",
    "/.gvfs-metadata/", "/.mozilla/", "/.thunderbird/",
    "/.dbus/", "/run/user/",
    # Snap apps churn
    "/snap/",
    # Print spooler + ansible runs
    "/etc/cups/", "/tmp/ansible_", "/tmp/.X", "/tmp/systemd-",
    # Package manager tempdirs and metadata (dnf/yum/apt/rpm)
    "/tmp/tmpdir.", "/repodata/",
    "/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/",
    "/var/lib/dnf/", "/var/lib/apt/", "/var/lib/rpm/",
    # systemd transient drop-ins
    "/run/systemd/",
    # Wazuh agent self-monitoring
    "/var/ossec/queue/", "/var/ossec/logs/", "/var/ossec/tmp/",
    # Log rotation artifacts
    "/var/log/journal/", ".log.1", ".gz.tmp", ".log.gz",
    # Python / pip installs triggered by Ansible
    "/lib/python", "/site-packages/", "/__pycache__/",
    # SSH known_hosts churned by scan/connect activity
    "/.ssh/known_hosts",
    # Windows WinRM temp paths (forwarded lowercase by Wazuh)
    "\\\\appdata\\\\local\\\\temp\\\\", "/appdata/local/temp/",
    "\\\\windows\\\\temp\\\\", "/windows/temp/",
    "\\\\users\\\\admini",
    "\\\\programdata\\\\microsoft\\\\windows\\\\wer\\\\",
    "\\\\windows\\\\prefetch\\\\",
    "\\\\windows\\\\system32\\\\winevt\\\\logs\\\\",
    "\\\\wazuh-agent\\\\", "ossec-agent",
    "\\\\tmp\\\\ansible-tmp-",
    # iptables save files — modified by block_ip playbook, not attacks
    "/etc/sysconfig/iptables", "/etc/iptables/rules",
    "/var/lib/sentinel-ai/", "/run/xtables.lock",
    # Temp files — never attacks
    "/tmp/", "/var/tmp/", "/dev/shm/",
    # apt/dpkg temp files
    "apt-key-gpghome", ".dpkg-", ".apt-",
    # webshell uploads dir — deleted by rearm, not an attack
    "/dvwa/hackable/uploads/",
    # dnsdist sed temp files
    "dnsdist/sed", "dnsdist/tmp",
    # sed/awk temp files
    "/etc/dnsdist/sed", "/etc/dnsdist/tmp",
    # Windows: C# compiler (csc.exe) temp artifacts spawned by Ansible/WinRM
    # itself under AppData\Local\Temp — prevents a FIM self-noise feedback loop
    # (win playbook runs -> csc.exe writes temp -> FIM fires -> playbook runs...)
    "\\appdata\\local\\temp\\",
    ".cmdline",
    "/var/log/nginx/",
    "/var/www/sentinel",
    "/etc/nginx/",
)

# Tracks (rule_id, agent_name) -> last dispatch timestamp (monotonic)
_recent_dispatches: dict = {}



# Windows agents use an allowlist approach for FIM — only critical paths dispatch
_FIM_WINDOWS_AGENTS = {"srv-ad-dns", "srv-ftp"}
_FIM_WINDOWS_CRITICAL_PATHS = (
    # System binaries — modification = rootkit/tamper
    "\\system32\\", "\\syswow64\\",
    "\\windows\\system32\\drivers\\",
    # Startup persistence
    "\\currentversion\\run", "\\currentversion\\runonce",
    "\\windows\\startup\\",
    # Scheduled tasks
    "\\system32\\tasks\\", "\\syswow64\\tasks\\",
    # Hosts file tampering
    "\\system32\\drivers\\etc\\hosts",
    # Credential stores
    "\\system32\\config\\sam", "\\system32\\config\\system",
    # Our monitored sentinel paths
    "c:\\sentinel", "\\tasks\\sentinel",
)
def _is_fim_noise(alert: dict) -> bool:
    """Return True if a FIM alert path matches a known noise pattern.

    For Windows agents (srv-ad-dns, srv-ftp), we use an ALLOWLIST approach:
    only dispatch if the path IS security-relevant. All other Windows FIM
    is Ansible/WinRM churn and has zero SOC value.

    For Linux agents we use the existing denylist (_FIM_NOISE_PATTERNS).
    """
    syscheck = alert.get("syscheck") or alert.get("data", {}).get("syscheck") or {}
    path = (syscheck.get("path") or "").lower()
    agent_name = (alert.get("agent") or {}).get("name", "")
    if not path:
        return False

    # Windows agents: allowlist approach — noise unless path is critical
    if agent_name in _FIM_WINDOWS_AGENTS:
        is_critical = any(crit in path for crit in _FIM_WINDOWS_CRITICAL_PATHS)
        return not is_critical  # noise=True if NOT critical

    # Linux agents: denylist approach — noise if path matches noise pattern
    return any(pat in path for pat in _FIM_NOISE_PATTERNS)


def _should_dispatch(alert: dict, level: int) -> tuple[bool, str]:
    """Decide whether an alert should reach the orchestrator.

    Returns (allow, reason). reason is empty when allowed; populated
    with a short tag when skipped (for logging).
    """
    rule = alert.get("rule") or {}
    try:
        rule_id = int(rule.get("id", 0))
    except (TypeError, ValueError):
        rule_id = 0
    agent_name = (alert.get("agent") or {}).get("name") or ""

    if not DISABLE_NOISE_FILTER:
        if rule_id in HARD_SKIP_RULES:
            return False, f"hard_skip_rule_{rule_id}"
        if rule_id in _FIM_RULES and _is_fim_noise(alert):
            return False, "fim_path_noise"

    # Per (rule_id, agent_name) dedup — category-aware window
    # FIM rules churn heavily; give them a 5-minute window
    # Scan rules generate bursts; give them 2 minutes
    # Everything else: default window (60s)
    import time
    if rule_id in _FIM_RULES:
        effective_window = max(DISPATCH_DEDUP_WINDOW_S, 300.0)  # 5 min for FIM
    elif rule_id in {86601, 87702, 40503, 40116, 40117}:
        effective_window = max(DISPATCH_DEDUP_WINDOW_S, 120.0)  # 2 min for scans
    else:
        effective_window = DISPATCH_DEDUP_WINDOW_S
    key = (rule_id, agent_name)
    now = time.monotonic()
    last = _recent_dispatches.get(key)
    if last is not None and now - last < effective_window:
        return False, "dedup"
    _recent_dispatches[key] = now

    # Periodic cleanup of stale entries to avoid unbounded memory growth
    if len(_recent_dispatches) > 5000:
        cutoff = now - DISPATCH_DEDUP_WINDOW_S * 2
        _recent_dispatches.clear()  # cheap reset; data is just timestamps
        _recent_dispatches[key] = now
        del cutoff

    return True, ""


def _decode(raw: Any) -> dict | None:
    """Decode a redis pubsub payload into an alert dict, or None on failure."""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None
    return None


async def dispatch_alerts(orchestrator) -> None:
    """Background task: forever consume Redis pubsub messages and
    dispatch each alert to the orchestrator."""
    redis = get_redis()
    pubsub = redis.subscribe(ALERT_CHANNEL)
    logger.info("alert_dispatcher.started", channel=ALERT_CHANNEL,
                min_level=DISPATCH_MIN_LEVEL)

    loop = asyncio.get_event_loop()

    def _next_message():
        # Blocking call; runs in executor.
        # timeout lets us yield control periodically and is also how we
        # respond to cancellation cleanly.
        return pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)

    while True:
        try:
            msg = await loop.run_in_executor(None, _next_message)
            if not msg:
                # No message in window — keep looping
                await asyncio.sleep(0)
                continue

            alert = _decode(msg.get("data"))
            if alert is None:
                logger.warning("alert_dispatcher.decode_failed",
                               raw_type=type(msg.get("data")).__name__)
                continue

            level = (alert.get("rule") or {}).get("level", 0)
            try:
                level = int(level)
            except (TypeError, ValueError):
                level = 0
            if level < DISPATCH_MIN_LEVEL and rule_id not in STATIC_RULE_MAP:
                logger.debug("alert_dispatcher.skip_low_level",
                             level=level, min_level=DISPATCH_MIN_LEVEL)
                continue

            allow, reason = _should_dispatch(alert, level)
            if not allow:
                logger.debug("alert_dispatcher.skip",
                             reason=reason,
                             rule_id=(alert.get("rule") or {}).get("id"),
                             agent=(alert.get("agent") or {}).get("name"))
                continue

            try:
                result = await orchestrator.process_alert(alert)
                _rule   = alert.get("rule") or {}
                _data   = alert.get("data") or {}
                _syscheck = alert.get("syscheck") or {}
                _winev  = (_data.get("win") or {}).get("eventdata") or {}
                _ctx    = (
                    _syscheck.get("path") or
                    _data.get("srcip") or _data.get("src_ip") or
                    _winev.get("ipAddress") or
                    _data.get("dstip") or ""
                )
                logger.info(
                    "alert_dispatcher.processed",
                    rule_id=_rule.get("id"),
                    rule_desc=(_rule.get("description") or "")[:80],
                    context=_ctx,
                    level=level,
                    incident_id=result.get("incident_id"),
                    severity=result.get("severity"),
                    dispatched=result.get("dispatch", {}).get("executed"),
                )
            except Exception as exc:
                logger.warning("alert_dispatcher.process_failed",
                               error=str(exc),
                               rule_id=(alert.get("rule") or {}).get("id"))

        except asyncio.CancelledError:
            logger.info("alert_dispatcher.cancelled")
            try:
                pubsub.unsubscribe(ALERT_CHANNEL)
                pubsub.close()
            except Exception:
                pass
            raise
        except Exception as exc:
            # Don't let the loop die on transient errors
            logger.error("alert_dispatcher.loop_error", error=str(exc))
            await asyncio.sleep(2)

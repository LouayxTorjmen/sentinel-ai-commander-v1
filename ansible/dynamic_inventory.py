#!/usr/bin/env python3
"""
Dynamic Ansible inventory from Wazuh Manager API.

Replaces the old hardcoded inventory. Pulls the live agent list from
Wazuh, classifies each agent by OS, emits per-OS connection vars, and
writes ansible/inventory/hosts.ini.

Key properties:
  - No hardcoded IPs. Everything pulled from the Wazuh agent registry.
  - OS-aware: Linux agents get SSH connection, Windows agents get WinRM.
  - Self-healing: if an agent is gone from Wazuh, it disappears from
    the inventory. If a new one appears, it shows up on the next pass.
  - Status-filtered: only "active" agents become remediation targets.
    Disconnected/never_connected agents are written to an [unreachable]
    group so playbooks skip them gracefully instead of timing out.
  - Includes the manager itself for local/docker exec playbooks.

Run modes:
  one-shot:   python3 dynamic_inventory.py
  daemon:     python3 dynamic_inventory.py --watch [--interval 60]

Environment variables:
  WAZUH_API_URL          - e.g. https://sentinel-wazuh-manager:55000
  WAZUH_API_USER         - manager API user (default: wazuh-wui)
  WAZUH_API_PASSWORD     - manager API password (required)
  INVENTORY_PATH         - output file (default: /ansible/inventory/hosts.ini)
  SSH_KEY_PATH           - private key for Linux agents (default: /ansible/keys/id_rsa)
  WINDOWS_USER           - WinRM username for Windows agents (required for Win)
  WINDOWS_PASSWORD       - WinRM password (required for Win)
  INVENTORY_INTERVAL     - daemon poll interval seconds (default: 60)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib3
from pathlib import Path
from typing import Any

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Config ───────────────────────────────────────────────────────────
WAZUH_API_URL     = os.getenv("WAZUH_API_URL", "https://sentinel-wazuh-manager:55000")
WAZUH_API_USER    = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS    = os.getenv("WAZUH_API_PASSWORD", "")
INVENTORY_PATH    = Path(os.getenv("INVENTORY_PATH", "/ansible/inventory/hosts.ini"))
SSH_KEY_PATH      = os.getenv("SSH_KEY_PATH", "/ansible/keys/id_rsa")
WINDOWS_USER      = os.getenv("WINDOWS_USER", "")
LINUX_USER        = os.getenv("LINUX_USER", "louay")
try:
    LINUX_USER_OVERRIDES = json.loads(os.getenv("LINUX_USER_OVERRIDES", "{}"))
except Exception:
    LINUX_USER_OVERRIDES = {}

# Agent names that are always Linux regardless of API OS detection
LINUX_OS_OVERRIDES   = set(os.getenv("LINUX_OS_OVERRIDES",   "").split(",")) - {""}
WINDOWS_OS_OVERRIDES = set(os.getenv("WINDOWS_OS_OVERRIDES", "").split(",")) - {""}

# Static IP overrides for agents that register with "any" as IP
try:
    AGENT_IP_OVERRIDES = json.loads(os.getenv("AGENT_IP_OVERRIDES", "{}"))
except Exception:
    AGENT_IP_OVERRIDES = {}
LINUX_BECOME_PW   = os.getenv("LINUX_BECOME_PASSWORD", "")
WINDOWS_PASSWORD  = os.getenv("WINDOWS_PASSWORD", "")

# Per-host credential overrides. JSON dict in env var:
#   WINDOWS_USER_OVERRIDES='{"srv-ftp": "Louay-Windows"}'
#   WINDOWS_PASSWORD_OVERRIDES='{"srv-ftp": "Louay@2002"}'
# Hosts not in the dict use the default WINDOWS_USER / WINDOWS_PASSWORD.
import json as _json
try:
    WINDOWS_USER_OVERRIDES = _json.loads(os.getenv("WINDOWS_USER_OVERRIDES", "{}"))
except _json.JSONDecodeError:
    WINDOWS_USER_OVERRIDES = {}
try:
    WINDOWS_PASSWORD_OVERRIDES = _json.loads(os.getenv("WINDOWS_PASSWORD_OVERRIDES", "{}"))
except _json.JSONDecodeError:
    WINDOWS_PASSWORD_OVERRIDES = {}
DEFAULT_INTERVAL  = int(os.getenv("INVENTORY_INTERVAL", "60"))


# ─── Wazuh API helpers ───────────────────────────────────────────────

def get_token() -> str:
    """Authenticate to the Wazuh manager API and return a JWT."""
    if not WAZUH_API_PASS:
        die("WAZUH_API_PASSWORD env var is required")
    r = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=False, timeout=15,
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def list_agents(token: str) -> list[dict[str, Any]]:
    """Return every enrolled agent (limit 1000 is the API max)."""
    r = requests.get(
        f"{WAZUH_API_URL}/agents",
        headers={"Authorization": f"Bearer {token}"},
        params={"limit": 1000},
        verify=False, timeout=30,
    )
    r.raise_for_status()
    return r.json()["data"]["affected_items"]


# ─── OS classification ───────────────────────────────────────────────

def classify_os(agent: dict) -> str:
    name = agent.get("name", "")
    if name in LINUX_OS_OVERRIDES:
        return "linux"
    if name in WINDOWS_OS_OVERRIDES:
        return "windows"
    """Return 'linux', 'windows', or 'unknown' for an agent dict.

    Wazuh's agent payload has os.platform ('ubuntu', 'rhel', 'centos',
    'windows', etc.). We normalise to two buckets because the Ansible
    connection plugin choice depends only on the family.
    """
    os_info = agent.get("os") or {}
    platform = (os_info.get("platform") or "").lower()
    name     = (os_info.get("name") or "").lower()
    uname    = (os_info.get("uname") or "").lower()

    if "windows" in platform or "windows" in name or "windows" in uname:
        return "windows"
    if platform in ("ubuntu", "debian", "rhel", "centos", "rocky",
                    "almalinux", "fedora", "kali", "opensuse-leap",
                    "amazon", "linux"):
        return "linux"
    if "linux" in uname:
        return "linux"
    return "unknown"


# ─── Inventory rendering ─────────────────────────────────────────────

def render_inventory(agents: list[dict]) -> str:
    """Produce the hosts.ini text from the agent list."""
    lines: list[str] = []
    lines.append("# AUTO-GENERATED by dynamic_inventory.py — DO NOT EDIT BY HAND")
    lines.append(f"# Last refresh : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    lines.append(f"# Source       : {WAZUH_API_URL}/agents")
    lines.append("")

    # The manager itself, accessible via docker exec
    lines.append("[wazuh_managers]")
    lines.append("sentinel-wazuh-manager "
                 "ansible_host=sentinel-wazuh-manager "
                 "ansible_connection=docker")
    lines.append("")

    linux_active:    list[tuple[str, str]] = []
    windows_active:  list[tuple[str, str]] = []
    unreachable:     list[tuple[str, str]] = []
    unknown_os:      list[tuple[str, str]] = []

    for a in agents:
        agent_id = a.get("id")
        if agent_id == "000":
            continue  # skip the manager pseudo-agent
        name = a.get("name") or f"agent-{agent_id}"
        ip   = a.get("ip") or a.get("registerIP") or ""
        if ip in ("any", "", None):
            ip = AGENT_IP_OVERRIDES.get(name, "")
            if not ip:
                continue
        status = (a.get("status") or "").lower()
        os_type = classify_os(a)

        if status != "active":
            # Force-active agents in LINUX_OS_OVERRIDES regardless of Wazuh status
            # (e.g. srv-dns-bind may show disconnected but is reachable via SSH)
            if name in LINUX_OS_OVERRIDES:
                linux_active.append((name, ip))
            else:
                unreachable.append((name, ip))
            continue
        if os_type == "linux":
            linux_active.append((name, ip))
        elif os_type == "windows":
            windows_active.append((name, ip))
        else:
            unknown_os.append((name, ip))

    # Per-host blocks - one section per OS family with proper connection vars
    lines.append("[linux_agents]")
    # Agents that need password auth instead of key auth
    LINUX_PASSWORD_AGENTS = set(os.getenv("LINUX_PASSWORD_AGENTS", "srv-dns-bind").split(",")) - {""}

    for name, ip in sorted(linux_active):
        if name in LINUX_PASSWORD_AGENTS:
            lines.append(
                f"{name} ansible_host={ip} "
                f"ansible_user={LINUX_USER_OVERRIDES.get(name, LINUX_USER)} "
                f"ansible_password={LINUX_BECOME_PW} "
                + (f"ansible_become_password={LINUX_BECOME_PW} " if LINUX_BECOME_PW else "")
                + f"ansible_ssh_common_args='-o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no' "
                f"ansible_connection=ssh "
                f"ansible_python_interpreter=auto_silent"
            )
        else:
            lines.append(
                f"{name} ansible_host={ip} "
                f"ansible_user={LINUX_USER_OVERRIDES.get(name, LINUX_USER)} "
                + (f"ansible_become_password={LINUX_BECOME_PW} " if LINUX_BECOME_PW else "")
                + f"ansible_ssh_private_key_file={SSH_KEY_PATH} "
                f"ansible_connection=ssh "
                f"ansible_python_interpreter=auto_silent"
            )
    lines.append("")

    # Windows hosts: only ansible_host on the host line; everything else
    # (connection plugin, transport, default creds) lives in the group
    # vars block below. Per-host credential overrides come from
    # WINDOWS_USER_OVERRIDES / WINDOWS_PASSWORD_OVERRIDES env vars OR
    # from host_vars/<name>.yml files, which Ansible auto-loads.
    lines.append("[windows_agents]")
    for name, ip in sorted(windows_active):
        # Per-host inline overrides (env-driven, deployment-time)
        user_override = WINDOWS_USER_OVERRIDES.get(name)
        pass_override = WINDOWS_PASSWORD_OVERRIDES.get(name)
        parts = [f"{name}", f"ansible_host={ip}"]
        if user_override:
            parts.append(f"ansible_user={user_override}")
        if pass_override:
            parts.append(f"ansible_password={pass_override}")
        lines.append(" ".join(parts))
    lines.append("")

    # Group-level defaults for every Windows host. Per-host overrides
    # above OR a host_vars/<name>.yml file win because Ansible's variable
    # precedence puts host vars above group vars.
    if windows_active:
        lines.append("[windows_agents:vars]")
        if WINDOWS_USER:
            lines.append(f"ansible_user={WINDOWS_USER}")
        if WINDOWS_PASSWORD:
            lines.append(f"ansible_password={WINDOWS_PASSWORD}")
        lines.append("ansible_connection=winrm")
        lines.append("ansible_winrm_transport=ntlm")
        lines.append("ansible_winrm_server_cert_validation=ignore")
        lines.append("ansible_port=5985")
        lines.append("")

    # Disconnected hosts: visible but playbooks skip them via the
    # [unreachable] group. The dispatcher can also check this group
    # before deciding to call a playbook on an offline host.
    lines.append("[unreachable]")
    for name, ip in sorted(unreachable):
        lines.append(f"{name} ansible_host={ip}  # status != active")
    lines.append("")

    if unknown_os:
        lines.append("[unknown_os]")
        for name, ip in sorted(unknown_os):
            lines.append(f"{name} ansible_host={ip}  # OS could not be classified")
        lines.append("")

    # All-hosts vars (only apply where they're meaningful)
    lines.append("[all:vars]")
    lines.append("ansible_ssh_common_args=-o StrictHostKeyChecking=no "
                 "-o UserKnownHostsFile=/dev/null "
                 "-o ConnectTimeout=10")
    lines.append("")

    # Convenience parent group so existing playbooks using `linux_victims`
    # keep working without edits during the transition.
    lines.append("[linux_victims:children]")
    lines.append("linux_agents")
    lines.append("")

    lines.append("[windows_victims:children]")
    lines.append("windows_agents")
    lines.append("")

    return "\n".join(lines) + "\n"


# ─── Diff + write ────────────────────────────────────────────────────

def write_if_changed(path: Path, new_content: str) -> bool:
    """Write only when content differs. Returns True if file changed."""
    try:
        old = path.read_text() if path.exists() else ""
    except OSError:
        old = ""
    if old == new_content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_content)
    return True


def summarise(agents: list[dict]) -> str:
    counts = {"linux_active": 0, "windows_active": 0, "unreachable": 0,
              "unknown": 0, "skipped_manager": 0, "no_ip": 0}
    for a in agents:
        if a.get("id") == "000":
            counts["skipped_manager"] += 1
            continue
        ip = a.get("ip") or a.get("registerIP") or ""
        if ip in ("any", "", None):
            counts["no_ip"] += 1
            continue
        status = (a.get("status") or "").lower()
        os_type = classify_os(a)
        if status != "active":
            counts["unreachable"] += 1
        elif os_type == "linux":
            counts["linux_active"] += 1
        elif os_type == "windows":
            counts["windows_active"] += 1
        else:
            counts["unknown"] += 1
    return (
        f"linux_active={counts['linux_active']} "
        f"windows_active={counts['windows_active']} "
        f"unreachable={counts['unreachable']} "
        f"unknown_os={counts['unknown']} "
        f"no_ip={counts['no_ip']}"
    )


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# ─── Entrypoint ──────────────────────────────────────────────────────

def refresh_once() -> bool:
    """One pass: fetch agents, render inventory, write if changed."""
    try:
        token = get_token()
        agents = list_agents(token)
    except Exception as e:
        print(f"[refresh] FAIL during fetch: {e}", file=sys.stderr)
        return False
    content = render_inventory(agents)
    changed = write_if_changed(INVENTORY_PATH, content)
    summary = summarise(agents)
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if changed:
        print(f"[{timestamp}] inventory UPDATED -> {INVENTORY_PATH}  {summary}")
    else:
        print(f"[{timestamp}] inventory unchanged                   {summary}")
    return True


def watch_loop(interval: int) -> None:
    print(f"[watch] starting daemon (poll every {interval}s)")
    while True:
        refresh_once()
        time.sleep(interval)


def main():
    p = argparse.ArgumentParser(description="Dynamic Wazuh -> Ansible inventory")
    p.add_argument("--watch", action="store_true",
                   help="Run forever; refresh on a schedule")
    p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                   help=f"Watch mode poll interval seconds (default {DEFAULT_INTERVAL})")
    p.add_argument("--once", action="store_true",
                   help="One-shot refresh and exit (default behavior)")
    args = p.parse_args()
    if args.watch:
        watch_loop(args.interval)
    else:
        ok = refresh_once()
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

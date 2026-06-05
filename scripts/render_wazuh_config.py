#!/usr/bin/env python3
"""
SENTINEL-AI — Wazuh Configuration Renderer
==========================================
Generates Wazuh configuration files from templates + environment variables.

Run this script BEFORE starting the Wazuh stack in any new environment.
It reads subnet and IP configuration from environment variables (or .env)
and writes the correct values into:
  - wazuh/config/manager/ossec.conf
  - wazuh/config/manager/local_rules.xml
  - wazuh/config/certs/certs.yml

Usage:
  python3 scripts/render_wazuh_config.py          # render all configs
  python3 scripts/render_wazuh_config.py --check  # validate env vars only

Environment variables (add to .env):
  SENTINEL_AGENT_SUBNETS        Comma-separated CIDRs where Wazuh agents live
                                Default: 10.50.0.0/24
  SENTINEL_MANAGEMENT_SUBNETS   Comma-separated CIDRs for management traffic
                                Default: 10.60.0.0/24
  SENTINEL_ATTACKER_SUBNETS     Comma-separated CIDRs for attacker/red-team range
                                Default: 10.70.0.0/24
  SENTINEL_ATTACKER_IP          Specific attacker IP for exfiltration detection rule
                                Default: 10.70.0.10
  WAZUH_DOCKER_BRIDGE_SUBNET    Docker bridge subnet used by Wazuh containers
                                Default: 172.30.0.0/16
  WAZUH_MANAGER_INTERNAL_IP     Wazuh manager Docker internal IP
                                Default: 172.29.0.10
  WAZUH_INDEXER_INTERNAL_IP     Wazuh indexer Docker internal IP
                                Default: 172.29.0.11
  WAZUH_DASHBOARD_INTERNAL_IP   Wazuh dashboard Docker internal IP
                                Default: 172.29.0.12
"""

import os
import sys
import re
from pathlib import Path

BASE = Path(__file__).parent.parent  # ~/sentinel-ai-commander/


# ── Load .env if present ──────────────────────────────────────────────────────

def load_env(env_path: Path) -> None:
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key not in os.environ:  # env takes priority over .env file
            os.environ[key] = value


load_env(BASE / ".env")


# ── Read configuration ────────────────────────────────────────────────────────

def get(var: str, default: str) -> str:
    return os.getenv(var, default).strip()


AGENT_SUBNETS     = [s.strip() for s in get("SENTINEL_AGENT_SUBNETS",      "10.50.0.0/24").split(",") if s.strip()]
MGMT_SUBNETS      = [s.strip() for s in get("SENTINEL_MANAGEMENT_SUBNETS", "10.60.0.0/24").split(",") if s.strip()]
ATTACKER_SUBNETS  = [s.strip() for s in get("SENTINEL_ATTACKER_SUBNETS",   "10.70.0.0/24").split(",") if s.strip()]
ATTACKER_IP       = get("SENTINEL_ATTACKER_IP",          "10.70.0.10")
DOCKER_BRIDGE     = get("WAZUH_DOCKER_BRIDGE_SUBNET",    "172.30.0.0/16")
MANAGER_IP        = get("WAZUH_MANAGER_INTERNAL_IP",     "172.29.0.10")
INDEXER_IP        = get("WAZUH_INDEXER_INTERNAL_IP",     "172.29.0.11")
DASHBOARD_IP      = get("WAZUH_DASHBOARD_INTERNAL_IP",   "172.29.0.12")

# All subnets allowed to send logs to the Wazuh manager
ALLOWED_SUBNETS = AGENT_SUBNETS + MGMT_SUBNETS + [DOCKER_BRIDGE]


# ── Validation ────────────────────────────────────────────────────────────────

def check() -> bool:
    import ipaddress
    ok = True
    print("Configuration values:")
    print(f"  SENTINEL_AGENT_SUBNETS      : {AGENT_SUBNETS}")
    print(f"  SENTINEL_MANAGEMENT_SUBNETS : {MGMT_SUBNETS}")
    print(f"  SENTINEL_ATTACKER_SUBNETS   : {ATTACKER_SUBNETS}")
    print(f"  SENTINEL_ATTACKER_IP        : {ATTACKER_IP}")
    print(f"  WAZUH_DOCKER_BRIDGE_SUBNET  : {DOCKER_BRIDGE}")
    print(f"  WAZUH_MANAGER_INTERNAL_IP   : {MANAGER_IP}")
    print(f"  WAZUH_INDEXER_INTERNAL_IP   : {INDEXER_IP}")
    print(f"  WAZUH_DASHBOARD_INTERNAL_IP : {DASHBOARD_IP}")
    print()
    for subnet in AGENT_SUBNETS + MGMT_SUBNETS + ATTACKER_SUBNETS + [DOCKER_BRIDGE]:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            print(f"  ERROR: invalid subnet: {subnet}")
            ok = False
    for ip in [ATTACKER_IP, MANAGER_IP, INDEXER_IP, DASHBOARD_IP]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(f"  ERROR: invalid IP: {ip}")
            ok = False
    if ok:
        print("All values valid.")
    return ok


# ── ossec.conf ────────────────────────────────────────────────────────────────

def render_ossec_conf() -> None:
    template_path = BASE / "wazuh/config/manager/ossec.conf.template"
    output_path   = BASE / "wazuh/config/manager/ossec.conf"

    if not template_path.exists():
        print(f"  ERROR: template not found: {template_path}")
        return

    content = template_path.read_text()

    # Build the dynamic <allowed-ips> block
    allowed_lines = "\n".join(
        f"    <allowed-ips>{subnet}</allowed-ips>"
        for subnet in ALLOWED_SUBNETS
    )

    # Replace ALL occurrences of the old hardcoded allowed-ips blocks
    # The pattern matches one or more consecutive <allowed-ips> lines
    content = re.sub(
        r"(\s*<allowed-ips>[0-9./]+</allowed-ips>\n)+",
        "\n" + allowed_lines + "\n",
        content,
    )

    # Also replace the internal IP match rule at line ~310
    # This rule filters out internal IPs from certain alerts
    all_internal = AGENT_SUBNETS + MGMT_SUBNETS
    # Build a regex-compatible match string using the first two octets of each subnet
    prefixes = []
    for subnet in all_internal:
        parts = subnet.split(".")
        if len(parts) >= 2:
            prefixes.append(f"{parts[0]}.{parts[1]}.")
    # Remove duplicates
    prefixes = list(dict.fromkeys(prefixes))
    match_str = "|".join(prefixes)

    content = re.sub(
        r"<match>([0-9.|]+)</match>",
        f"<match>{match_str}</match>",
        content,
        count=1,
    )

    output_path.write_text(content)
    print(f"  Written: {output_path.relative_to(BASE)}")


# ── local_rules.xml ───────────────────────────────────────────────────────────

def render_local_rules() -> None:
    template_path = BASE / "wazuh/config/manager/local_rules.xml.template"
    output_path   = BASE / "wazuh/config/manager/local_rules.xml"

    if not template_path.exists():
        print(f"  ERROR: template not found: {template_path}")
        return

    content = template_path.read_text()

    # Rule 100720: attacker VLAN srcip
    # If multiple attacker subnets, use the first one (Wazuh <srcip> supports one CIDR)
    # For multiple subnets, the rule would need to be duplicated — out of scope here
    primary_attacker_subnet = ATTACKER_SUBNETS[0] if ATTACKER_SUBNETS else "10.70.0.0/24"
    content = re.sub(
        r"<srcip>[0-9./]+</srcip>",
        f"<srcip>{primary_attacker_subnet}</srcip>",
        content,
    )

    # Rule 100730: specific attacker IP in data.dest_ip field
    content = re.sub(
        r'(<field name="data\.dest_ip">)[0-9.]+(<\/field>)',
        rf"\g<1>{ATTACKER_IP}\g<2>",
        content,
    )

    # Also update any comment references to the old IPs so documentation stays accurate
    content = content.replace("10.70.0.0/24", primary_attacker_subnet)
    content = content.replace("10.70.0.10", ATTACKER_IP)

    output_path.write_text(content)
    print(f"  Written: {output_path.relative_to(BASE)}")


# ── certs.yml ─────────────────────────────────────────────────────────────────

def render_certs_yml() -> None:
    template_path = BASE / "wazuh/config/certs/certs.yml.template"
    output_path   = BASE / "wazuh/config/certs/certs.yml"

    if not template_path.exists():
        print(f"  ERROR: template not found: {template_path}")
        return

    content = template_path.read_text()

    # Replace the three internal Docker IPs
    # Template has them at fixed positions for indexer, manager, dashboard
    # The names (wazuh.indexer, wazuh.manager, wazuh.dashboard) stay the same
    content = re.sub(r'(name: wazuh\.indexer\s*\n\s*ip: ")[0-9.]+"',
                     f'\\g<1>{INDEXER_IP}"', content)
    content = re.sub(r'(name: wazuh\.manager\s*\n\s*ip: ")[0-9.]+"',
                     f'\\g<1>{MANAGER_IP}"', content)
    content = re.sub(r'(name: wazuh\.dashboard\s*\n\s*ip: ")[0-9.]+"',
                     f'\\g<1>{DASHBOARD_IP}"', content)

    output_path.write_text(content)
    print(f"  Written: {output_path.relative_to(BASE)}")
    print(f"  NOTE: Run scripts/gen_certs.sh after this to regenerate TLS certificates.")


# ── hosts.ini documentation ───────────────────────────────────────────────────

def check_hosts_ini() -> None:
    hosts_ini = BASE / "ansible/inventory/hosts.ini"
    template  = BASE / "ansible/inventory/hosts.ini.template"

    if not template.exists():
        tmpl_content = """\
# =============================================================================
# SENTINEL-AI — Ansible Inventory (AUTO-GENERATED)
# =============================================================================
# DO NOT EDIT THIS FILE BY HAND.
# It is generated automatically by ansible/dynamic_inventory.py
# which queries the live Wazuh agent list.
#
# To regenerate:
#   python3 ansible/dynamic_inventory.py > ansible/inventory/hosts.ini
#
# Required environment variables:
#   WAZUH_API_URL          e.g. https://wazuh-manager:55000
#   WAZUH_API_USER         e.g. wazuh-wui
#   WAZUH_API_PASSWORD     your Wazuh API password
#   SENTINEL_WINDOWS_AGENTS comma-separated list of Windows agent names
#   LINUX_PASSWORD_AGENTS  comma-separated list of Linux agents using password auth
#
# The file is excluded from git (.gitignore) because it contains
# environment-specific IPs and credentials. Never commit it.
# =============================================================================

[wazuh_managers]
# auto-populated

[linux_agents]
# auto-populated

[windows_agents]
# auto-populated

[windows_agents:vars]
ansible_user=Administrator
ansible_connection=winrm
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
ansible_port=5985
"""
        template.write_text(tmpl_content)
        print(f"  Written: ansible/inventory/hosts.ini.template")

    if not hosts_ini.exists():
        print(f"  INFO: hosts.ini not found — run: python3 ansible/dynamic_inventory.py > ansible/inventory/hosts.ini")
    else:
        print(f"  OK: hosts.ini exists (not tracked by git)")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    check_only = "--check" in sys.argv

    print("SENTINEL-AI Wazuh Configuration Renderer")
    print("=" * 50)

    if not check() and check_only:
        sys.exit(1)

    if check_only:
        print("Check passed. Run without --check to write files.")
        sys.exit(0)

    print("\nRendering configuration files...")
    render_ossec_conf()
    render_local_rules()
    render_certs_yml()

    print("\nChecking inventory...")
    check_hosts_ini()

    print("\nDone. Next steps for a new environment:")
    print("  1. Verify wazuh/config/manager/ossec.conf has the correct subnets")
    print("  2. Run scripts/gen_certs.sh to regenerate TLS certificates")
    print("  3. Run: python3 ansible/dynamic_inventory.py > ansible/inventory/hosts.ini")
    print("  4. Start the Wazuh stack: cd wazuh && docker compose up -d")

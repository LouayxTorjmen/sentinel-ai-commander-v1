#!/usr/bin/env python3
"""
SENTINEL-AI Commander — Container Management Tool
==================================================
Usage:
  python3 sentinel.py start [service...]
  python3 sentinel.py stop [service...]
  python3 sentinel.py restart [service...]
  python3 sentinel.py status
  python3 sentinel.py logs <service> [--tail N]
  python3 sentinel.py build [service...]
  python3 sentinel.py exec <service> <command...>
  python3 sentinel.py remove [service...]
  python3 sentinel.py up          # start everything
  python3 sentinel.py down        # stop everything
  python3 sentinel.py health      # show health of all services
  python3 sentinel.py autostart   # install as systemd service (Linux/WSL2)

Services: all | wazuh | infra | ai | <container_name>
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

# ── Colour helpers ──────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}✓{RESET}  {msg}")
def warn(msg): print(f"{YELLOW}!{RESET}  {msg}")
def err(msg):  print(f"{RED}✗{RESET}  {msg}")
def info(msg): print(f"{CYAN}→{RESET}  {msg}")
def header(msg): print(f"\n{BOLD}{CYAN}{msg}{RESET}\n{'─'*60}")

# ── Project layout ──────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR
ENV_FILE     = PROJECT_ROOT / ".env"
WAZUH_DIR    = PROJECT_ROOT / "wazuh"

# Container → stack mapping
STACKS = {
    "sentinel-wazuh-indexer":   {"dir": WAZUH_DIR,    "compose": "docker-compose.yml"},
    "sentinel-wazuh-manager":   {"dir": WAZUH_DIR,    "compose": "docker-compose.yml"},
    "sentinel-wazuh-dashboard": {"dir": WAZUH_DIR,    "compose": "docker-compose.yml"},
    "sentinel-postgres":        {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
    "sentinel-redis":           {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
    "sentinel-nginx":           {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
    "sentinel-suricata":        {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
    "sentinel-ollama":          {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
    "sentinel-ai-agents":       {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
    "sentinel-ansible-runner":  {"dir": PROJECT_ROOT, "compose": "docker-compose.yml"},
}

# Service group aliases
GROUPS = {
    "wazuh": ["sentinel-wazuh-indexer", "sentinel-wazuh-manager", "sentinel-wazuh-dashboard"],
    "infra": ["sentinel-postgres", "sentinel-redis", "sentinel-nginx"],
    "ai":    ["sentinel-ollama", "sentinel-ai-agents", "sentinel-ansible-runner"],
    "ids":   ["sentinel-suricata"],
    "all":   list(STACKS.keys()),
}

# Startup order (dependencies first)
STARTUP_ORDER = [
    "sentinel-wazuh-indexer",
    "sentinel-wazuh-manager",
    "sentinel-wazuh-dashboard",
    "sentinel-postgres",
    "sentinel-redis",
    "sentinel-suricata",
    "sentinel-nginx",
    "sentinel-ollama",
    "sentinel-ansible-runner",
    "sentinel-ai-agents",
]

# ── Docker helpers ──────────────────────────────────────────────────────────

def run(cmd: List[str], cwd: Optional[Path] = None, capture: bool = False,
        timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a command, streaming output unless capture=True."""
    env = os.environ.copy()
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        # Load .env into environment
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env.setdefault(k.strip(), v.strip())

    kwargs = dict(cwd=cwd or PROJECT_ROOT, env=env, timeout=timeout)
    if capture:
        kwargs.update(capture_output=True, text=True)
    else:
        kwargs.update(text=True)
    return subprocess.run(cmd, **kwargs)


def docker_compose(args: List[str], stack_dir: Path) -> subprocess.CompletedProcess:
    cmd = ["docker", "compose", "--env-file", str(PROJECT_ROOT / ".env")] + args
    return run(cmd, cwd=stack_dir)


def get_container_status(name: str) -> dict:
    """Return dict with status, health, ports for a container."""
    result = run(
        ["docker", "inspect", name,
         "--format", "{{json .State}}"],
        capture=True
    )
    if result.returncode != 0:
        return {"running": False, "health": "not_found", "status": "not_found"}
    try:
        state = json.loads(result.stdout.strip())
        health = state.get("Health", {})
        return {
            "running": state.get("Running", False),
            "status":  state.get("Status", "unknown"),
            "health":  health.get("Status", "none") if health else "none",
            "started": state.get("StartedAt", "")[:19],
        }
    except Exception:
        return {"running": False, "health": "error", "status": "error"}


def resolve_services(names: List[str]) -> List[str]:
    """Expand group names and return list of container names."""
    result = []
    for name in names:
        if name in GROUPS:
            result.extend(GROUPS[name])
        elif name in STACKS:
            result.append(name)
        else:
            # Try prefix match
            matches = [c for c in STACKS if c.endswith(name) or name in c]
            if matches:
                result.extend(matches)
            else:
                warn(f"Unknown service: {name}")
    # Deduplicate preserving order
    seen = set()
    return [x for x in result if not (x in seen or seen.add(x))]


def get_stack_dir(container: str) -> Path:
    return STACKS.get(container, {}).get("dir", PROJECT_ROOT)


# ── Commands ────────────────────────────────────────────────────────────────

def cmd_status(args):
    """Show status of all containers."""
    header("SENTINEL-AI Commander — Container Status")

    col_w = [30, 12, 10, 20]
    header_row = (f"{'Container':<{col_w[0]}} {'Status':<{col_w[1]}} "
                  f"{'Health':<{col_w[2]}} {'Started':<{col_w[3]}}")
    print(header_row)
    print("─" * sum(col_w))

    for name in STARTUP_ORDER:
        s = get_container_status(name)
        status_str  = s["status"]
        health_str  = s["health"]
        started_str = s["started"]

        if s["running"]:
            status_col = f"{GREEN}{status_str:<{col_w[1]}}{RESET}"
        else:
            status_col = f"{RED}{status_str:<{col_w[1]}}{RESET}"

        if health_str == "healthy":
            health_col = f"{GREEN}{health_str:<{col_w[2]}}{RESET}"
        elif health_str in ("unhealthy", "error"):
            health_col = f"{RED}{health_str:<{col_w[2]}}{RESET}"
        elif health_str == "not_found":
            health_col = f"{YELLOW}{'missing':<{col_w[2]}}{RESET}"
        else:
            health_col = f"{YELLOW}{health_str:<{col_w[2]}}{RESET}"

        print(f"{name:<{col_w[0]}} {status_col} {health_col} {started_str}")

    print()


def cmd_up(args):
    """Start all stacks in correct order."""
    header("Starting all stacks")

    # 1. Wazuh stack
    info("Starting Wazuh stack...")
    docker_compose(["up", "-d"], WAZUH_DIR)

    # Wait for indexer
    info("Waiting for Wazuh indexer to be healthy...")
    for _ in range(60):
        s = get_container_status("sentinel-wazuh-indexer")
        if s["health"] == "healthy":
            ok("Wazuh indexer healthy")
            break
        time.sleep(5)
        print(".", end="", flush=True)
    print()

    # 2. Main stack
    info("Starting main stack (infra + suricata + AI)...")
    docker_compose(["up", "-d"], PROJECT_ROOT)

    time.sleep(5)
    cmd_status(args)


def cmd_down(args):
    """Stop all stacks."""
    header("Stopping all stacks")
    info("Stopping main stack...")
    docker_compose(["down"], PROJECT_ROOT)
    info("Stopping Wazuh stack...")
    docker_compose(["down"], WAZUH_DIR)
    ok("All stacks stopped")


def cmd_start(args):
    """Start specific services."""
    services = resolve_services(args.services) if args.services else GROUPS["all"]
    header(f"Starting: {', '.join(services)}")

    # Group by stack directory
    main_services, wazuh_services = [], []
    for s in services:
        if get_stack_dir(s) == WAZUH_DIR:
            wazuh_services.append(s)
        else:
            main_services.append(s)

    # Start in dependency order
    ordered = [s for s in STARTUP_ORDER if s in services]

    for container in ordered:
        stack_dir = get_stack_dir(container)
        service_name = container.replace("sentinel-wazuh-", "wazuh-").replace("sentinel-", "")
        info(f"Starting {container}...")
        docker_compose(["up", "-d", service_name], stack_dir)

    time.sleep(3)
    for container in ordered:
        s = get_container_status(container)
        if s["running"]:
            ok(f"{container}: {s['status']} ({s['health']})")
        else:
            err(f"{container}: {s['status']}")


def cmd_stop(args):
    """Stop specific services."""
    services = resolve_services(args.services) if args.services else GROUPS["all"]
    header(f"Stopping: {', '.join(services)}")

    # Stop in reverse order
    for container in reversed(STARTUP_ORDER):
        if container not in services:
            continue
        service_name = container.replace("sentinel-wazuh-", "wazuh-").replace("sentinel-", "")
        stack_dir = get_stack_dir(container)
        info(f"Stopping {container}...")
        docker_compose(["stop", service_name], stack_dir)
        ok(f"{container} stopped")


def cmd_restart(args):
    """Restart specific services."""
    services = resolve_services(args.services) if args.services else GROUPS["all"]
    header(f"Restarting: {', '.join(services)}")
    cmd_stop(args)
    time.sleep(2)
    cmd_start(args)


def cmd_logs(args):
    """Tail logs for a service."""
    services = resolve_services([args.service])
    if not services:
        err(f"Unknown service: {args.service}")
        return
    container = services[0]
    tail = getattr(args, "tail", 50)
    info(f"Logs for {container} (last {tail} lines, Ctrl+C to exit)...")
    run(["docker", "logs", "--tail", str(tail), "-f", container])


def cmd_build(args):
    """Build images for specific services."""
    services = resolve_services(args.services) if args.services else ["ai-agents", "nginx", "ansible-runner", "suricata"]
    header(f"Building: {', '.join(services)}")

    main_build = [s.replace("sentinel-", "") for s in services
                  if get_stack_dir(s if s.startswith("sentinel-") else f"sentinel-{s}") == PROJECT_ROOT]
    if main_build:
        info(f"Building main stack services: {main_build}")
        docker_compose(["build"] + main_build, PROJECT_ROOT)


def cmd_exec(args):
    """Execute a command in a container."""
    services = resolve_services([args.service])
    if not services:
        err(f"Unknown service: {args.service}")
        return
    container = services[0]
    info(f"Executing in {container}: {' '.join(args.command)}")
    run(["docker", "exec", "-it", container] + args.command)


def cmd_remove(args):
    """Remove containers (and optionally volumes)."""
    services = resolve_services(args.services) if args.services else []
    if not services:
        err("Specify services to remove or use 'all'")
        return
    header(f"Removing: {', '.join(services)}")
    for container in services:
        info(f"Removing {container}...")
        run(["docker", "rm", "-f", container], capture=True)
        ok(f"{container} removed")


def cmd_health(args):
    """Show detailed health including API checks."""
    header("SENTINEL-AI Health Check")

    import urllib.request
    import ssl

    checks = [
        ("AI Agents API",       "http://localhost:50010/health"),
        ("Ansible Runner API",  "http://localhost:50011/health"),
        ("Nginx Health (HTTP)", "http://localhost:50020/nginx-health"),
        ("Nginx Health (HTTPS)","https://localhost:50021/nginx-health"),
    ]

    cmd_status(args)

    print(f"\n{'API Endpoint':<35} {'Status':<10} {'Response'}")
    print("─" * 70)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for name, url in checks:
        try:
            req = urllib.request.urlopen(url, timeout=5, context=ctx if url.startswith("https") else None)
            data = json.loads(req.read().decode())
            status = data.get("status", "unknown")
            col = GREEN if status == "ok" else YELLOW
            print(f"{name:<35} {col}{'ok':<10}{RESET} {json.dumps(data)[:60]}")
        except Exception as e:
            print(f"{name:<35} {RED}{'fail':<10}{RESET} {str(e)[:60]}")


def cmd_autostart(args):
    """Install as a systemd service so everything starts on boot."""
    header("Installing autostart service")

    script_path = Path(__file__).resolve()
    python_path = sys.executable

    service_content = f"""[Unit]
Description=SENTINEL-AI Commander — Auto-start all containers
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory={PROJECT_ROOT}
ExecStart={python_path} {script_path} up
ExecStop={python_path} {script_path} down
TimeoutStartSec=300
TimeoutStopSec=120
User=root

[Install]
WantedBy=multi-user.target
"""

    service_path = Path("/etc/systemd/system/sentinel-ai.service")

    # Check if running in WSL2
    is_wsl = False
    try:
        with open("/proc/version") as f:
            is_wsl = "microsoft" in f.read().lower()
    except Exception:
        pass

    if is_wsl:
        warn("WSL2 detected — systemd may not be fully supported.")
        warn("Writing startup script to /etc/profile.d/ instead.")
        startup_script = f"""#!/bin/bash
# SENTINEL-AI auto-start (WSL2)
if [ "$(id -u)" = "0" ] || groups | grep -q docker; then
    # Enable IP forwarding for VM connectivity
    echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    # Start SENTINEL-AI if not running
    if ! docker ps | grep -q sentinel-ai-agents; then
        cd {PROJECT_ROOT}
        {python_path} {script_path} up &>/tmp/sentinel-autostart.log &
    fi
fi
"""
        profile_path = Path("/etc/profile.d/sentinel-ai.sh")
        try:
            profile_path.write_text(startup_script)
            profile_path.chmod(0o755)
            ok(f"Startup script written to {profile_path}")
        except PermissionError:
            err("Run as root: sudo python3 sentinel.py autostart")
            return

        # Also create a Windows Task Scheduler suggestion
        print(f"""
{YELLOW}For Windows Task Scheduler (runs on login):{RESET}
  1. Open Task Scheduler → Create Task
  2. Trigger: At log on
  3. Action: wsl.exe -d Ubuntu -u root -- bash -c "cd {PROJECT_ROOT} && python3 {script_path} up"
  4. Run with highest privileges: ✓
""")
    else:
        try:
            service_path.write_text(service_content)
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "sentinel-ai.service"])
            ok(f"Service installed: {service_path}")
            ok("Enabled for autostart on boot")
            info("Run 'systemctl start sentinel-ai' to start now")
        except PermissionError:
            err("Run as root: sudo python3 sentinel.py autostart")
        except FileNotFoundError:
            err("systemctl not found — are you on a systemd system?")


def cmd_ip_forward(args):
    """Enable IP forwarding (needed for VM connectivity in WSL2)."""
    try:
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
        ok("IP forwarding enabled")
    except Exception as e:
        err(f"Failed: {e}")


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL-AI Commander — Container Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Services/groups:
  all       — all containers
  wazuh     — wazuh-indexer, wazuh-manager, wazuh-dashboard
  infra     — postgres, redis, nginx
  ai        — ollama, ai-agents, ansible-runner
  ids       — suricata
  <name>    — exact container name or partial match

Examples:
  python3 sentinel.py up
  python3 sentinel.py status
  python3 sentinel.py start wazuh ai
  python3 sentinel.py restart sentinel-ai-agents
  python3 sentinel.py logs sentinel-ai-agents --tail 100
  python3 sentinel.py exec sentinel-ai-agents python3 -c "import ai_agents"
  python3 sentinel.py build ai-agents
  python3 sentinel.py health
  python3 sentinel.py autostart
""")

    sub = parser.add_subparsers(dest="command")

    # up / down
    sub.add_parser("up",   help="Start all stacks in correct order")
    sub.add_parser("down", help="Stop all stacks")

    # start / stop / restart
    for cmd_name in ("start", "stop", "restart"):
        p = sub.add_parser(cmd_name, help=f"{cmd_name.capitalize()} services")
        p.add_argument("services", nargs="*", help="Service names or groups")

    # status
    sub.add_parser("status", help="Show container status")

    # health
    sub.add_parser("health", help="Full health check including API endpoints")

    # logs
    p = sub.add_parser("logs", help="Tail container logs")
    p.add_argument("service", help="Container name or group")
    p.add_argument("--tail", type=int, default=50, help="Number of lines (default 50)")

    # build
    p = sub.add_parser("build", help="Build container images")
    p.add_argument("services", nargs="*", help="Service names (default: all buildable)")

    # exec
    p = sub.add_parser("exec", help="Execute command in a container")
    p.add_argument("service", help="Container name")
    p.add_argument("command", nargs="+", help="Command to run")

    # remove
    p = sub.add_parser("remove", help="Remove containers")
    p.add_argument("services", nargs="+", help="Service names or 'all'")

    # autostart
    sub.add_parser("autostart", help="Install autostart service (systemd or WSL2 profile)")

    # ip-forward
    sub.add_parser("ip-forward", help="Enable IP forwarding for VM connectivity")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    dispatch = {
        "up":         cmd_up,
        "down":       cmd_down,
        "start":      cmd_start,
        "stop":       cmd_stop,
        "restart":    cmd_restart,
        "status":     cmd_status,
        "health":     cmd_health,
        "logs":       cmd_logs,
        "build":      cmd_build,
        "exec":       cmd_exec,
        "remove":     cmd_remove,
        "autostart":  cmd_autostart,
        "ip-forward": cmd_ip_forward,
    }

    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

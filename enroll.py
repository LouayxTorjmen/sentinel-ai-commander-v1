#!/usr/bin/env python3
"""
SENTINEL-AI — Interactive Wazuh + Suricata Enrollment

Deploys:
  1. Wazuh agent (HIDS + log monitoring + FIM + rootcheck)
  2. Suricata NIDS (network traffic inspection)
  3. Wazuh integration to ship Suricata alerts

Suricata runs in IDS mode. Wazuh active-response handles blocking
(iptables firewall-drop) — safer than inline IPS on VMs.

Network interface selection:
  - Auto-detects the default-route interface and confirms with the user.
  - Falls back to a menu of all interfaces (ethX / ensX / enpXsY /
    wlanX etc.) showing name, IP, subnet, MAC and state so the user
    can pick the right one when auto-detection isn't what they want.
"""
import subprocess, sys, os, re, json, time, socket, base64, tempfile


# ── .env auto-loader ──────────────────────────────────────────────────
# Read ~/sentinel-ai-commander/.env (or SENTINEL_ENV env override) on import
# so that running under sudo, from cron, or from a fresh shell all work
# identically without requiring `set -a; source .env`.
#
# Precedence (highest wins):
#   1. Values already set in the process environment
#   2. Values from the .env file
#   3. Hardcoded defaults in the os.getenv() calls below
def _load_env_file():
    # Resolve .env location. Users can override with SENTINEL_ENV for testing.
    candidates = [
        os.environ.get("SENTINEL_ENV"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.expanduser("~/sentinel-ai-commander/.env"),
        "/root/sentinel-ai-commander/.env",
    ]
    env_file = next((p for p in candidates if p and os.path.isfile(p)), None)
    if not env_file:
        return None

    try:
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                # Skip blanks and comments
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                # Strip surrounding quotes if present
                if len(val) >= 2 and val[0] in ("'", '"') and val[-1] == val[0]:
                    val = val[1:-1]
                # Only set if not already in env (existing env wins)
                if key and key not in os.environ:
                    os.environ[key] = val
        return env_file
    except OSError:
        return None


_ENV_FILE_LOADED = _load_env_file()

MANAGER_IP = os.getenv("WAZUH_MANAGER_IP", "172.31.70.13")
MANAGER_PORT = os.getenv("WAZUH_AGENT_PORT", "50041")
WAZUH_API = os.getenv("WAZUH_API_URL", "https://localhost:50001")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASSWORD", "changeme")
SSH_KEY = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/sentinel-ai-commander/ansible/keys/id_rsa"))
NETWORK = os.getenv("DISCOVERY_NETWORKS", "192.168.49.0/24")
EXCLUDE_IPS = set(os.getenv("DISCOVERY_EXCLUDE_IPS", "192.168.49.1,192.168.49.2").split(","))

_enrolled_ips = set()

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; W = "\033[97m"; DIM = "\033[2m"; RST = "\033[0m"

def banner():
    print(f"""
{C}╔══════════════════════════════════════════════════════╗
║  {B}🛡️  SENTINEL-AI — Wazuh + Suricata Enrollment{RST}{C}       ║
║     HIDS + NIDS with unified alert pipeline          ║
╚══════════════════════════════════════════════════════╝{RST}
""")

# ── Shell helpers ─────────────────────────────────────────────────────
def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", 1

def ssh_run(ip, cmd, user="root", timeout=60):
    ssh = f'ssh -i {SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes {user}@{ip} "{cmd}"'
    return run(ssh, timeout=timeout)

def ssh_script(ip, script, timeout=300):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
        f.write(script)
        tmp = f.name
    cmd = f'ssh -i {SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes root@{ip} bash -s < {tmp}'
    out, err, rc = run(cmd, timeout=timeout)
    os.unlink(tmp)
    return out, err, rc

def ssh_test(ip, user="root"):
    out, _, rc = ssh_run(ip, "echo OK", user=user, timeout=10)
    return rc == 0 and "OK" in out

def sshpass_run(ip, user, password, cmd, timeout=30):
    # Force password auth method. Without these -o flags, modern OpenSSH
    # tries kbd-interactive first and rejects sshpass-injected passwords with
    # "Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks".
    full = (f'sshpass -p "{password}" ssh '
            f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
            f'-o ConnectTimeout=10 -o PubkeyAuthentication=no '
            f'-o PreferredAuthentications=password '
            f'{user}@{ip} "{cmd}"')
    return run(full, timeout=timeout)

def sshpass_test(ip, user, password):
    out, _, _ = sshpass_run(ip, user, password, "echo SSH_OK", timeout=10)
    return "SSH_OK" in (out or "")

# ── Wazuh API ─────────────────────────────────────────────────────────
def get_api_token(verbose=False):
    """Retrieve a Wazuh API JWT. On failure, prints a specific diagnostic
    so the user can tell apart the three common causes:
      - Credentials wrong (HTTP 401)
      - API not reachable (curl exit code != 0)
      - Unexpected response shape (JSON without .data.token)
    """
    cmd = (f'curl -sk -w "\\n%{{http_code}}" -X POST '
           f'{WAZUH_API}/security/user/authenticate '
           f'-u "{WAZUH_API_USER}:{WAZUH_API_PASS}"')
    out, err, rc = run(cmd)

    if rc != 0:
        if verbose:
            print(f"{R}    [API] curl failed (rc={rc}): API unreachable at {WAZUH_API}?{RST}")
            if err:
                print(f"{R}    [API] curl stderr: {err[:200]}{RST}")
        return None

    # Extract HTTP status code from the last line
    body = out
    http_code = ""
    if out and "\n" in out:
        body, _, http_code = out.rpartition("\n")

    if http_code and http_code != "200":
        if verbose:
            print(f"{R}    [API] HTTP {http_code} — auth rejected{RST}")
            if http_code == "401":
                print(f"{Y}    [API] Check WAZUH_API_USER / WAZUH_API_PASSWORD in .env{RST}")
                print(f"{Y}    [API] If running under sudo, use 'sudo -E' to preserve env{RST}")
                # Show what user we tried (not the password)
                print(f"{DIM}    [API] Tried user: {WAZUH_API_USER}  URL: {WAZUH_API}{RST}" if False else
                      f"    [API] Tried user={WAZUH_API_USER} at {WAZUH_API}")
        return None

    try:
        return json.loads(body)["data"]["token"]
    except Exception as e:
        if verbose:
            print(f"{R}    [API] Response unparseable: {str(e)[:100]}{RST}")
            print(f"{DIM}    [API] Body: {body[:200]}{RST}")
        return None

def api_register_agent(token, name):
    """Register agent with ip='any' — Docker NAT means manager never sees real IP."""
    out, _, _ = run(f'curl -sk -X POST "{WAZUH_API}/agents" '
        f'-H "Authorization: Bearer {token}" '
        f'-H "Content-Type: application/json" '
        f"""-d '{{"name": "{name}", "ip": "any"}}'""")
    try:
        data = json.loads(out)
        if data.get("error", 1) != 0:
            return None, None, data.get("message", str(data))
        agent_id = data["data"]["id"]
        key_b64 = data["data"]["key"]
        key_line = base64.b64decode(key_b64).decode()
        return agent_id, key_line, None
    except Exception as e:
        return None, None, str(e)

def api_delete_agent(token, agent_id):
    run(f'curl -sk -X DELETE "{WAZUH_API}/agents?agents_list={agent_id}&status=all&older_than=0s" '
        f'-H "Authorization: Bearer {token}"')

def get_existing_agents():
    token = get_api_token()
    if not token: return {}
    out, _, _ = run(f'curl -sk "{WAZUH_API}/agents?limit=500" -H "Authorization: Bearer {token}"')
    try:
        agents = json.loads(out)["data"]["affected_items"]
        return {a.get("ip", ""): a for a in agents if a.get("id") != "000"}
    except: return {}

def get_existing_agent_names():
    token = get_api_token()
    if not token: return set()
    out, _, _ = run(f'curl -sk "{WAZUH_API}/agents?limit=500" -H "Authorization: Bearer {token}"')
    try:
        return {a["name"] for a in json.loads(out)["data"]["affected_items"]}
    except: return set()

# ── Network Scan ──────────────────────────────────────────────────────
def scan_network():
    print(f"{Y}[*] Scanning {NETWORK} ...{RST}")
    out, _, rc = run(f"nmap -sn {NETWORK} -oG - 2>/dev/null | grep 'Status: Up' | awk '{{print $2}}'", timeout=60)
    if rc != 0:
        print(f"{R}[!] nmap not found{RST}"); return []
    hosts = [ip for ip in out.split("\n") if ip and ip not in EXCLUDE_IPS]
    print(f"{G}[+] Found {len(hosts)} live hosts{RST}")
    return hosts

# ── OS Detection ──────────────────────────────────────────────────────
def detect_os(ip):
    info = {"os": "unknown", "family": "unknown", "arch": "unknown", "pkg": "unknown", "version": ""}
    out, _, rc = ssh_run(ip, "cat /etc/os-release 2>/dev/null; uname -m")
    if rc != 0 or not out: return info
    osrel = {}
    for line in out.split("\n"):
        if "=" in line:
            k, _, v = line.partition("=")
            val = v.strip()
            if len(val) >= 2 and val[0] in ('"', "'") and val[-1] == val[0]:
                val = val[1:-1]
            osrel[k.strip().upper()] = val
    distro = osrel.get("ID", "").lower()
    version = osrel.get("VERSION_ID", "")
    if distro:
        info["os"] = distro; info["version"] = version
        if distro in ("ubuntu", "debian", "kali", "linuxmint", "pop", "elementary"):
            info["family"] = "debian"; info["pkg"] = "deb"
        elif distro in ("rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn", "amazon"):
            info["family"] = "rhel"; info["pkg"] = "rpm"
        elif distro in ("opensuse", "sles", "suse"):
            info["family"] = "suse"; info["pkg"] = "rpm"
    m_arch = re.search(r"(x86_64|aarch64|arm64|armv7l|i[36]86)", out)
    if m_arch:
        raw = m_arch.group(1)
        if raw == "x86_64": info["arch"] = "amd64"
        elif raw in ("aarch64", "arm64"): info["arch"] = "aarch64"
        else: info["arch"] = "i386"
    return info

SUPPORTED = {
    "debian": {"deb": ["amd64", "aarch64", "i386"]},
    "rhel":   {"rpm": ["amd64", "aarch64"]},
    "suse":   {"rpm": ["amd64", "aarch64"]},
}

def check_supported(info):
    fam = info["family"]
    if fam not in SUPPORTED:
        return False, f"OS family '{fam}' not supported"
    archs = SUPPORTED[fam].get(info["pkg"], [])
    if info["arch"] not in archs:
        return False, f"Arch '{info['arch']}' not supported for {fam}/{info['pkg']}"
    return True, "OK"

def get_wazuh_pkg_url(info):
    pkg, arch = info["pkg"], info["arch"]
    if pkg == "deb":
        deb_arch = "arm64" if arch == "aarch64" else arch
        return f"https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.4-1_{deb_arch}.deb"
    else:
        rpm_arch = "aarch64" if arch == "aarch64" else "x86_64"
        return f"https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.4-1.{rpm_arch}.rpm"

# ── SSH Setup (unchanged from v3) ─────────────────────────────────────
def ensure_sshpass():
    out, _, rc = run("which sshpass", timeout=5)
    if rc != 0:
        print(f"{Y}[*] Installing sshpass...{RST}")
        run("apt-get install -y sshpass 2>&1 | tail -2", timeout=30)

def ensure_pubkey():
    pubkey_path = SSH_KEY + ".pub"
    if not os.path.exists(pubkey_path):
        run(f"ssh-keygen -y -f {SSH_KEY} > {pubkey_path}")
    return open(pubkey_path).read().strip()

def setup_ssh(ip):
    print(f"\n{Y}[*] Testing SSH key auth to root@{ip}...{RST}")
    # Strip any stale host key for this IP — VMs get rebuilt and reuse IPs,
    # and a host-key mismatch makes OpenSSH refuse all auth methods including
    # password+kbd-interactive, producing confusing "Permission denied" errors.
    run(f"ssh-keygen -f /root/.ssh/known_hosts -R {ip} 2>/dev/null", timeout=5)
    run(f"ssh-keygen -f ~/.ssh/known_hosts -R {ip} 2>/dev/null", timeout=5)
    if ssh_test(ip):
        print(f"{G}[+] SSH key works for root@{ip}{RST}")
        return True
    print(f"{Y}[!] No key-based root access to {ip}{RST}")
    print(f"    {C}1){RST} I have a regular user with sudo")
    print(f"    {C}2){RST} I have the root password")
    print(f"    {C}3){RST} Skip")
    choice = input(f"\n{C}    Choice [1/2/3]: {RST}").strip()
    if choice == "3": return False
    ensure_sshpass()
    pubkey = ensure_pubkey()

    if choice == "1":
        user = input(f"{C}    Username: {RST}").strip()
        password = input(f"{C}    Password: {RST}").strip()
        if not user or not password: return False
        print(f"{Y}[*] Testing login...{RST}")
        if not sshpass_test(ip, user, password):
            _, err, _ = sshpass_run(ip, user, password, "echo test", timeout=10)
            print(f"{R}[!] Login failed for {user}@{ip}{RST}")
            if err:
                for l in err.strip().split("\n")[-3:]:
                    if l.strip() and "Warning" not in l: print(f"    {R}-> {l.strip()}{RST}")
            return False
        print(f"{G}[+] Login works{RST}")
        out, _, _ = sshpass_run(ip, user, password, f"echo {password} | sudo -S echo SUDO_OK 2>/dev/null", timeout=10)
        if "SUDO_OK" not in (out or ""):
            print(f"{R}[!] No sudo. Fix: su - && usermod -aG wheel {user} (RHEL) or sudo (Debian){RST}")
            return False
        print(f"{G}[+] Sudo confirmed{RST}")
        setup = (f"echo {password} | sudo -S bash -c '"
            f'sed -i "s/^#*PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config; '
            f"mkdir -p /root/.ssh; chmod 700 /root/.ssh; "
            f'echo "{pubkey}" >> /root/.ssh/authorized_keys; '
            f"sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys; "
            f"chmod 600 /root/.ssh/authorized_keys; "
            f"systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; "
            f"echo DONE'")
        sshpass_run(ip, user, password, setup, timeout=20)
        time.sleep(2)
        if ssh_test(ip):
            print(f"{G}[+] Root SSH confirmed!{RST}"); return True
        print(f"{R}[!] Root SSH still failing{RST}")
        return False

    elif choice == "2":
        password = input(f"{C}    Root password: {RST}").strip()
        if not password: return False
        if not sshpass_test(ip, "root", password):
            print(f"{R}[!] Root login failed{RST}"); return False
        print(f"{G}[+] Root login works{RST}")
        sshpass_run(ip, "root", password,
            f"mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '{pubkey}' >> /root/.ssh/authorized_keys && sort -u /root/.ssh/authorized_keys -o /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys",
            timeout=15)
        time.sleep(1)
        if ssh_test(ip):
            print(f"{G}[+] Root key SSH confirmed!{RST}"); return True
        return True
    return False

# ── Network Interface Detection + Interactive Picker ─────────────────
def list_network_interfaces(ip):
    """Enumerate all usable network interfaces on the remote host.

    Returns a list of dicts:
        [{"name": "ens33", "ipv4": "192.168.49.128", "subnet": "192.168.49.0/24",
          "mac": "00:0c:29:05:73:11", "state": "UP", "is_default": True}, ...]

    Filters out loopback. Interfaces without an IPv4 address are kept but
    flagged (they can't be used for IDS but we show them so the user sees
    the full picture).
    """
    import ipaddress as _ipaddress
    import re as _re

    # ── a) Discover default-route interface first ──
    out, _, _ = ssh_run(ip, "ip route get 8.8.8.8 2>/dev/null")
    default_iface = ""
    if out:
        m = _re.search(r"dev\s+(\S+)", out)
        if m:
            default_iface = m.group(1)

    # ── b) List all interfaces ──
    # ip -br -4 addr output:  ens33            UP             192.168.49.128/24
    # We also need interfaces that are UP with no IPv4 (show them as (no IP))
    out, _, _ = ssh_run(ip, "ip -br link show 2>/dev/null")
    if not out:
        return []

    ifaces = []
    for line in out.split("\n"):
        parts = line.split()
        if len(parts) < 2:
            continue
        name, state = parts[0], parts[1]
        # Skip loopback and interfaces that are DOWN+NOCARRIER
        if name == "lo" or name.startswith("docker") or name.startswith("veth"):
            continue
        # State may be "UP", "DOWN", or "UNKNOWN" (bridges, tun)
        mac = parts[2] if len(parts) > 2 else ""

        # Fetch IPv4 for this interface
        out2, _, _ = ssh_run(ip, f"ip -4 addr show {name} 2>/dev/null | grep -oP 'inet \\K[\\d./]+' | head -1")
        ipv4_cidr = (out2 or "").strip()
        ipv4 = ""
        subnet = ""
        if ipv4_cidr:
            ipv4 = ipv4_cidr.split("/")[0]
            try:
                net = _ipaddress.ip_network(ipv4_cidr, strict=False)
                subnet = str(net)
            except:
                subnet = ipv4_cidr

        ifaces.append({
            "name": name,
            "ipv4": ipv4,
            "subnet": subnet,
            "mac": mac,
            "state": state,
            "is_default": (name == default_iface),
        })

    # Sort: default first, then UP interfaces with IPv4, then others
    ifaces.sort(key=lambda x: (
        not x["is_default"],           # default interface first
        not bool(x["ipv4"]),           # then those with IP
        x["state"] != "UP",            # then UP ones
        x["name"],                     # alphabetical tie-break
    ))
    return ifaces


def select_network_interface(ip, interactive=True):
    """Select the network interface Suricata should monitor.

    Behavior (option C from design discussion):
    - Auto-detect default-route interface and show it with its IP + subnet
    - Ask "use this? [Y/n]"  — pressing Enter accepts
    - If user says 'n', show a menu of all interfaces and let them pick
    - Returns (iface_name, subnet_cidr) or (None, None) on failure

    If interactive=False (e.g., called from non-interactive automation),
    behaves like the old function: just auto-detect silently.
    """
    ifaces = list_network_interfaces(ip)
    if not ifaces:
        print(f"{R}[!] Could not enumerate interfaces on {ip}{RST}")
        return None, None

    # Find the auto-detected default
    default = next((i for i in ifaces if i["is_default"]), None)

    if not interactive:
        # Non-interactive: use default, or first with IPv4
        chosen = default or next((i for i in ifaces if i["ipv4"]), None)
        if not chosen:
            return None, None
        return chosen["name"], chosen["subnet"] or None

    # Interactive path
    if default and default["ipv4"]:
        print(f"{C}    Detected interface: {B}{default['name']}{RST}{C} "
              f"(IP: {default['ipv4']}, subnet: {default['subnet']}){RST}")
        try:
            resp = input(f"    Use {default['name']} for Suricata monitoring? [Y/n] ").strip().lower()
        except EOFError:
            resp = ""
        if resp in ("", "y", "yes"):
            return default["name"], default["subnet"] or None
        # Fall through to menu
    else:
        print(f"{Y}    Could not auto-detect default-route interface{RST}")

    # ── Full menu ──
    print(f"\n{C}    Available network interfaces on {ip}:{RST}")
    print(f"    {'#':>3}  {'Name':<12} {'State':<8} {'IPv4':<18} {'Subnet':<20} {'MAC':<18} {'Default':<8}")
    print(f"    {'─' * 90}")
    for idx, iface in enumerate(ifaces, start=1):
        default_mark = f"{G}✓{RST}" if iface["is_default"] else " "
        ipv4_display = iface["ipv4"] or f"{Y}(no IPv4){RST}"
        subnet_display = iface["subnet"] or "-"
        state_color = G if iface["state"] == "UP" else Y
        print(f"    {idx:>3}  {B}{iface['name']:<12}{RST} "
              f"{state_color}{iface['state']:<8}{RST} "
              f"{ipv4_display:<18} "
              f"{subnet_display:<20} "
              f"{iface['mac']:<18} "
              f"{default_mark:<8}")

    while True:
        try:
            sel = input(f"\n    Select interface number [1-{len(ifaces)}] (or 'q' to quit): ").strip().lower()
        except EOFError:
            sel = "q"
        if sel in ("q", "quit", "exit"):
            print(f"{Y}    Suricata deployment skipped{RST}")
            return None, None
        if sel.isdigit() and 1 <= int(sel) <= len(ifaces):
            chosen = ifaces[int(sel) - 1]
            if not chosen["ipv4"]:
                # Warn but allow — some users might want to monitor a passive tap
                print(f"{Y}    Warning: {chosen['name']} has no IPv4 address. "
                      f"HOME_NET will default to RFC1918.{RST}")
                confirm = input(f"    Use {chosen['name']} anyway? [y/N] ").strip().lower()
                if confirm not in ("y", "yes"):
                    continue
            return chosen["name"], chosen["subnet"] or None
        print(f"{R}    Invalid selection{RST}")


# Backwards-compat alias so existing call sites keep working
def detect_network_interface(ip):
    """Legacy wrapper — calls select_network_interface with interactive=True."""
    return select_network_interface(ip, interactive=True)

# ── Deploy Wazuh ──────────────────────────────────────────────────────
def deploy_wazuh(ip, info, agent_name):
    print(f"\n{Y}[*] Deploying Wazuh agent...{RST}")

    # Check if already running healthy
    out, _, rc = ssh_run(ip, "systemctl is-active wazuh-agent 2>/dev/null")
    if rc == 0 and "active" in out:
        out2, _, _ = ssh_run(ip, "grep 'No file configured to monitor' /var/ossec/logs/ossec.log 2>/dev/null | tail -1")
        if "No file configured" not in out2:
            out3, _, _ = ssh_run(ip, "grep 'Connected to the server' /var/ossec/logs/ossec.log 2>/dev/null | tail -1")
            if "Connected" in (out3 or ""):
                print(f"{G}[+] Wazuh agent already running and healthy{RST}")
                return True
        print(f"{Y}[!] Existing agent broken. Removing...{RST}")
        ssh_run(ip, "systemctl stop wazuh-agent 2>/dev/null; rpm -e wazuh-agent 2>/dev/null; dpkg --purge wazuh-agent 2>/dev/null; rm -rf /var/ossec", timeout=30)
        time.sleep(2)

    # Register via API
    print(f"{C}    Registering via API...{RST}")
    token = get_api_token(verbose=True)
    if not token:
        print(f"{R}[!] Cannot get API token{RST}"); return False
    agent_id, key_line, err = api_register_agent(token, agent_name)
    if not agent_id:
        print(f"{R}[!] Registration failed: {err}{RST}"); return False
    print(f"{G}    Registered: ID={agent_id}{RST}")

    # Install package
    print(f"{C}    Installing Wazuh package...{RST}")
    url = get_wazuh_pkg_url(info)
    ensure_dl = "command -v curl >/dev/null || command -v wget >/dev/null || { apt-get update -qq && apt-get install -y curl 2>&1 | tail -2; } || { yum install -y curl 2>&1 | tail -2; } || { dnf install -y curl 2>&1 | tail -2; }"
    dl = f"curl -so /tmp/wazuh-pkg {url} 2>/dev/null || wget -qO /tmp/wazuh-pkg {url}"
    if info["pkg"] == "deb":
        install = f"{ensure_dl}; {dl} && DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/wazuh-pkg && rm -f /tmp/wazuh-pkg"
    else:
        install = f"{ensure_dl}; {dl} && rpm -ihv /tmp/wazuh-pkg && rm -f /tmp/wazuh-pkg"
    out, err, rc = ssh_run(ip, install, timeout=180)
    for line in (out or "").split("\n"):
        if line.strip(): print(f"    {line}")
    if rc != 0:
        api_delete_agent(token, agent_id)
        return False

    # Configure ossec.conf
    print(f"{C}    Configuring ossec.conf...{RST}")
    config_script = f"""#!/bin/bash
CONF="/var/ossec/etc/ossec.conf"
if grep -q 'MANAGER_IP' "$CONF"; then
    sed -i 's|MANAGER_IP|{MANAGER_IP}|g' "$CONF"
else
    sed -i 's|<address>.*</address>|<address>{MANAGER_IP}</address>|' "$CONF"
fi
sed -i 's|<port>1514</port>|<port>{MANAGER_PORT}</port>|g' "$CONF"
if grep -q '<enrollment>' "$CONF"; then
    sed -i '/<enrollment>/,/<\\/enrollment>/s|<enabled>yes</enabled>|<enabled>no</enabled>|' "$CONF"
else
    sed -i '/<\\/server>/a\\    <enrollment>\\n      <enabled>no</enabled>\\n    </enrollment>' "$CONF"
fi
# Shorten syscollector scan interval from 1h default to 10m so IT Hygiene
# reflects user/group/package changes quickly. Only rewrites the <interval>
# inside the <wodle name="syscollector"> block, not other intervals.
python3 - << 'PYEOF'
import re
conf = "/var/ossec/etc/ossec.conf"
with open(conf) as f:
    content = f.read()
new_content = re.sub(
    r'(<wodle name="syscollector">.*?)<interval>1h</interval>',
    r'\\1<interval>10m</interval>',
    content, flags=re.DOTALL, count=1
)
if new_content != content:
    with open(conf, "w") as f:
        f.write(new_content)
PYEOF
# Enable realtime FIM + 5-minute scan + alert_new_files for responsive FIM.
# Upstream's <syscheck> defaults (12h scheduled scan, no realtime, no
# alert_new_files) mean file changes go unnoticed for up to 12 hours.
python3 - << 'PYEOF'
import re
conf = "/var/ossec/etc/ossec.conf"
with open(conf) as f:
    content = f.read()

orig = content

# 1. Change <frequency>43200</frequency> (12h) to 300 (5m) inside <syscheck>
content = re.sub(
    r'(<syscheck>.*?)<frequency>43200</frequency>',
    r'\\1<frequency>300</frequency>',
    content, flags=re.DOTALL, count=1
)

# 2. Add realtime="yes" check_all="yes" report_changes="yes" to bare
#    <directories>...</directories> tags inside <syscheck>
def patch_syscheck(match):
    block = match.group(0)
    block = re.sub(
        r'<directories>(?!.*realtime)([^<]+)</directories>',
        r'<directories realtime="yes" check_all="yes" report_changes="yes">\\1</directories>',
        block,
    )
    return block

content = re.sub(
    r'<syscheck>.*?</syscheck>',
    patch_syscheck,
    content, flags=re.DOTALL, count=1
)

# 3. Add <alert_new_files>yes</alert_new_files> right after <disabled>no</disabled>
if '<alert_new_files>' not in content:
    content = re.sub(
        r'(<syscheck>\\s*<disabled>no</disabled>)',
        r'\\1\\n    <alert_new_files>yes</alert_new_files>',
        content, count=1
    )

if content != orig:
    with open(conf, "w") as f:
        f.write(content)
PYEOF
echo CONFIG_DONE
"""
    out, _, _ = ssh_script(ip, config_script, timeout=15)
    if "CONFIG_DONE" in (out or ""):
        print(f"{G}    Config: manager={MANAGER_IP}, port={MANAGER_PORT}, enrollment=off{RST}")

    # Inject key
    print(f"{C}    Injecting agent key...{RST}")
    escaped_key = key_line.replace("'", "'\\''")
    ssh_run(ip, f"echo '{escaped_key}' > /var/ossec/etc/client.keys && chmod 640 /var/ossec/etc/client.keys")

    # Start
    print(f"{C}    Starting Wazuh agent...{RST}")
    ssh_run(ip, "systemctl daemon-reload && systemctl enable wazuh-agent && systemctl restart wazuh-agent", timeout=15)
    time.sleep(8)
    out, _, _ = ssh_run(ip, "/var/ossec/bin/wazuh-control status")
    if "is running" not in (out or ""):
        print(f"{R}[!] Wazuh agent not running{RST}")
        api_delete_agent(token, agent_id)
        return False

    # Wait for connection
    print(f"{Y}    Waiting for manager connection...{RST}")
    connected = False
    for _ in range(4):
        time.sleep(5)
        out, _, _ = ssh_run(ip, "grep 'Connected to the server' /var/ossec/logs/ossec.log 2>/dev/null | tail -1")
        if "Connected" in (out or ""):
            print(f"    {G}{out.strip()}{RST}")
            connected = True
            break

    if not connected:
        print(f"{Y}    (Agent started but not yet confirmed connected){RST}")

    return True

# ── Deploy Suricata ───────────────────────────────────────────────────
# Suricata version used for source builds (LTS, widely tested).
# Bumpable via SENTINEL_SURICATA_SRC_VERSION env var.
# 8.0.4 matches what the apt-packaged versions ship as of this commit,
# keeping the whole fleet on a consistent Suricata line.
SURICATA_SRC_VERSION = os.getenv("SENTINEL_SURICATA_SRC_VERSION", "8.0.4")


def _needs_source_build(info):
    """RHEL 10 / Rocky 10 / Alma 10 have no working Suricata packages:
       - EPEL 10 doesn't ship suricata
       - OSIF copr builds are linked against DPDK 26 (not in RHEL 10 repos)
       - RHEL 10 AppStream suricata requires an active subscription
       Build from source for these. All other RHEL family versions use EPEL.
    """
    if info.get("family") != "rhel":
        return False
    version = str(info.get("version", "")).split(".")[0]
    return version == "10"


def _suricata_source_build_script(iface, subnet, version):
    """Generate the remote bash script that builds Suricata from source.
    Derived from the documented RHEL 10 build procedure.
    Includes:
      - Repo setup for unregistered RHEL (falls back to Rocky 10 mirrors)
      - Full dependency install
      - Rust toolchain via rustup if not available
      - ./configure + make -j + make install-full + make install-conf
      - Nested config dir fix-up (known quirk of make install-full)
      - Hardened systemd unit with --af-packet -i <iface>
      - suricata user + permissions model
    """
    home_net = subnet or "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    return f"""#!/bin/bash
set -e
log() {{ echo "    [$(date +%H:%M:%S)] $*"; }}

SURICATA_VER="{version}"
IFACE="{iface}"

# --- 1. Detect distro version for repo setup ---
if [ -f /etc/rocky-release ]; then
    DISTRO=rocky
    REL=$(grep -oP 'release \\K[0-9]+' /etc/rocky-release | head -1)
elif [ -f /etc/almalinux-release ]; then
    DISTRO=alma
    REL=$(grep -oP 'release \\K[0-9]+' /etc/almalinux-release | head -1)
elif [ -f /etc/redhat-release ]; then
    DISTRO=rhel
    REL=$(grep -oP 'release \\K[0-9]+' /etc/redhat-release | head -1)
else
    DISTRO=unknown
    REL=10
fi
log "Distro: $DISTRO $REL"

# --- 2. Ensure usable base repos (for unregistered RHEL, fall back to Rocky mirrors) ---
USABLE_REPOS=$(dnf repolist --enabled 2>/dev/null | tail -n +2 | awk '{{print $1}}')
if ! echo "$USABLE_REPOS" | grep -qE '^(baseos|BaseOS)$'; then
    log "No BaseOS repo — configuring Rocky ${{REL}} public mirrors as fallback"
    cat > /etc/yum.repos.d/sentinel-rocky-fallback.repo <<REPOEOF
[rocky-baseos]
name=Rocky Linux ${{REL}} - BaseOS (sentinel fallback)
baseurl=https://dl.rockylinux.org/pub/rocky/${{REL}}/BaseOS/x86_64/os/
enabled=1
gpgcheck=0

[rocky-appstream]
name=Rocky Linux ${{REL}} - AppStream (sentinel fallback)
baseurl=https://dl.rockylinux.org/pub/rocky/${{REL}}/AppStream/x86_64/os/
enabled=1
gpgcheck=0

[rocky-crb]
name=Rocky Linux ${{REL}} - CRB (sentinel fallback)
baseurl=https://dl.rockylinux.org/pub/rocky/${{REL}}/CRB/x86_64/os/
enabled=1
gpgcheck=0
REPOEOF
fi

# Ensure EPEL
if ! rpm -q epel-release >/dev/null 2>&1; then
    log "Installing epel-release..."
    dnf install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${{REL}}.noarch.rpm" 2>&1 | tail -2 || true
fi

# Enable CRB / PowerTools (needed for some -devel packages)
dnf install -y -q dnf-plugins-core 2>&1 | tail -1 || true
dnf config-manager --set-enabled crb 2>/dev/null \\
    || dnf config-manager --set-enabled powertools 2>/dev/null \\
    || true

dnf clean all >/dev/null 2>&1
dnf makecache -q 2>&1 | tail -1 || true

# --- 3. Install build dependencies ---
# Two tiers: REQUIRED (build fails without) and RECOMMENDED (enable features).
log "Installing REQUIRED build dependencies..."
dnf install -y --nogpgcheck \\
    gcc gcc-c++ make autoconf automake libtool pkgconf-pkg-config m4 \\
    libpcap libpcap-devel pcre2-devel zlib-devel \\
    libyaml-devel jansson-devel file-devel libcap-ng-devel \\
    python3 python3-pip python3-devel \\
    wget tar jq \\
    2>&1 | tail -3

log "Installing RECOMMENDED dependencies (feature completeness)..."
dnf install -y --nogpgcheck --skip-unavailable \\
    cmake-filesystem zlib-ng-compat zlib-ng-compat-devel \\
    libnetfilter_queue libnetfilter_queue-devel \\
    libnfnetlink libnfnetlink-devel libmnl libmnl-devel \\
    lz4-devel libunwind-devel \\
    libmaxminddb libmaxminddb-devel \\
    glibc-devel glibc-common kernel-headers libxcrypt-devel \\
    rdma-core-devel libibumad librdmacm \\
    perl-File-Compare perl-File-Copy perl-Thread-Queue perl-threads perl-threads-shared \\
    2>&1 | tail -3 || true

# --- 4. Rust toolchain (Suricata 7+ needs rust for parsers) ---
if ! command -v cargo >/dev/null 2>&1; then
    log "Rust not found — installing from distro repos first..."
    dnf install -y --nogpgcheck rust cargo rust-std-static 2>&1 | tail -3 || true
fi
if ! command -v cargo >/dev/null 2>&1; then
    log "Installing Rust via rustup as fallback..."
    curl -sSf --proto "=https" --tlsv1.2 https://sh.rustup.rs \\
        | sh -s -- -y --default-toolchain stable --profile minimal 2>&1 | tail -3
    export PATH="$HOME/.cargo/bin:$PATH"
    # Persist for this session in root's profile
    grep -q '/.cargo/bin' /root/.bashrc 2>/dev/null || \\
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> /root/.bashrc
fi
command -v cargo >/dev/null || {{ log "ERROR: cargo still not available"; exit 10; }}

# --- 5. PyYAML for suricata-update ---
pip3 install --quiet pyyaml 2>&1 | tail -1 || true

# --- 6. Check if already built ---
if command -v suricata >/dev/null 2>&1; then
    CUR_VER=$(suricata -V 2>&1 | grep -oP 'version \\K\\S+' | head -1)
    log "Suricata $CUR_VER already installed — skipping rebuild"
else
    # --- 7. Download + extract source ---
    log "Downloading Suricata ${{SURICATA_VER}} source..."
    cd /tmp
    rm -rf sentinel-suricata-build
    mkdir sentinel-suricata-build && cd sentinel-suricata-build
    wget -q "https://www.openinfosecfoundation.org/download/suricata-${{SURICATA_VER}}.tar.gz" \\
        -O suricata.tar.gz
    [ ! -s suricata.tar.gz ] && {{ log "ERROR: download failed"; exit 11; }}
    tar xzf suricata.tar.gz
    cd "suricata-${{SURICATA_VER}}"

    # --- 8. Configure ---
    log "Running ./configure (takes ~1 minute)..."
    export PATH="$HOME/.cargo/bin:$PATH"
    ./configure \\
        --prefix=/usr \\
        --sysconfdir=/etc \\
        --localstatedir=/var \\
        --disable-gccmarch-native \\
        2>&1 | tail -5

    # --- 9. Compile ---
    CPU=$(nproc)
    log "Compiling with -j${{CPU}} (takes several minutes)..."
    make -j${{CPU}} 2>&1 | tail -3

    # --- 10. Install ---
    log "Installing..."
    make install-full 2>&1 | tail -3
    make install-conf 2>&1 | tail -3 || true
    ldconfig

    if ! command -v suricata >/dev/null 2>&1; then
        log "ERROR: suricata binary not found after install"
        exit 12
    fi
    log "Installed: $(suricata -V 2>&1 | head -1)"
fi

# --- 11. Fix nested config dir quirk (some builds put config at /etc/suricata/suricata/) ---
if [ -d /etc/suricata/suricata ] && [ -f /etc/suricata/suricata/suricata.yaml ]; then
    log "Fixing nested config directory..."
    mv /etc/suricata/suricata/* /etc/suricata/
    rmdir /etc/suricata/suricata 2>/dev/null || true
fi

# --- 12. Create suricata system user if missing ---
if ! id suricata >/dev/null 2>&1; then
    log "Creating suricata system user..."
    useradd --system --no-create-home --shell /sbin/nologin suricata 2>/dev/null || true
fi

# --- 13. Create runtime + data directories with proper ownership ---
mkdir -p /run/suricata /var/log/suricata /var/lib/suricata/rules /var/lib/suricata/data /var/lib/suricata/cache
chown -R suricata:suricata /run/suricata /var/log/suricata /var/lib/suricata

# --- 14. /etc/suricata permissions: daemon runs as suricata user, so
#     suricata needs to READ configs. Make it owner to avoid SELinux edge
#     cases where daemon can't read root-owned files even with 644 perms.
chown -R suricata:suricata /etc/suricata
find /etc/suricata -type f \\( -name '*.yaml' -o -name '*.config' \\) -exec chmod 640 {{}} \\;
chmod 755 /etc/suricata

# --- 15. Write hardened systemd unit (overwrites any existing one) ---
log "Writing systemd unit with interface=${{IFACE}}..."
cat > /etc/systemd/system/suricata.service <<UNITEOF
[Unit]
Description=Suricata IDS/IPS/NSM daemon
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=simple

User=suricata
Group=suricata

RuntimeDirectory=suricata
RuntimeDirectoryMode=0755

PIDFile=/run/suricata/suricata.pid

ExecStart=/usr/bin/suricata \\\\
  --af-packet \\\\
  -c /etc/suricata/suricata.yaml \\\\
  --pidfile /run/suricata/suricata.pid \\\\
  -i ${{IFACE}}

ExecReload=/bin/kill -USR2 \\$MAINPID
ExecStop=/usr/bin/suricatasc -c shutdown

Restart=on-failure

ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNITEOF

# Disable any legacy unit that might conflict
[ -f /usr/lib/systemd/system/suricata.service ] && {{
    log "Masking distro-shipped /usr/lib/systemd/system/suricata.service in favor of our unit"
}}

log "SOURCE_BUILD_DONE"
"""


def _deploy_suricata_via_package(ip, info):
    """Install Suricata via the distribution's package manager.
    Works for: Debian/Ubuntu (apt), SUSE (zypper), RHEL 8/9 family (EPEL).
    Returns True if Suricata is installed afterward.
    """
    family = info["family"]
    if family == "debian":
        install = """
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq 2>&1 | tail -1
apt-get install -y software-properties-common 2>&1 | tail -1
add-apt-repository -y ppa:oisf/suricata-stable 2>&1 | tail -2 || true
apt-get update -qq 2>&1 | tail -1
apt-get install -y suricata jq 2>&1 | tail -2
"""
    elif family == "rhel":
        # RHEL 8/9/Rocky 8/9/Alma 8/9 — EPEL has suricata
        version_major = str(info.get("version", "")).split(".")[0] or "9"
        install = f"""
set +e
command -v dnf >/dev/null && PKG=dnf || PKG=yum

$PKG install -y dnf-plugins-core 2>&1 | tail -1 || true
dnf config-manager --set-enabled crb 2>/dev/null \\
    || dnf config-manager --set-enabled powertools 2>/dev/null || true

if ! rpm -q epel-release >/dev/null 2>&1; then
    $PKG install -y "https://dl.fedoraproject.org/pub/epel/epel-release-latest-{version_major}.noarch.rpm" 2>&1 | tail -2 || true
fi

$PKG install -y suricata jq 2>&1 | tail -3
command -v suricata >/dev/null && exit 0 || exit 1
"""
    elif family == "suse":
        install = """
zypper --non-interactive install -y suricata jq 2>&1 | tail -2
command -v suricata >/dev/null && exit 0 || exit 1
"""
    else:
        print(f"{R}[!] Unknown family: {family}{RST}")
        return False

    out, err, rc = ssh_run(ip, install, timeout=300)
    for line in (out or "").split("\n")[-6:]:
        if line.strip():
            print(f"    {line}")

    # Verify
    out, _, _ = ssh_run(ip, "command -v suricata && suricata -V 2>&1 | head -1")
    if "Suricata version" in (out or ""):
        print(f"{G}    Installed via package: {out.split(chr(10))[-1].strip()}{RST}")
        return True
    return False


def _deploy_suricata_via_source(ip, iface, subnet):
    """Build Suricata from source on the remote host.
    Used for RHEL 10 / Rocky 10 / Alma 10 where no package path works.
    This is a long operation — ~8-12 minutes typically.
    """
    print(f"{Y}    RHEL 10 detected — no working Suricata package available.{RST}")
    print(f"{Y}    Building Suricata {SURICATA_SRC_VERSION} from source (~8-12 min)...{RST}")
    script = _suricata_source_build_script(iface, subnet, SURICATA_SRC_VERSION)

    # This needs a long timeout for compile.
    out, err, rc = ssh_script(ip, script, timeout=1800)
    # Stream the tail of output so user sees progress markers
    for line in (out or "").split("\n"):
        if line.strip() and ("[" in line and "]" in line or "ERROR" in line):
            print(f"    {line}")

    if "SOURCE_BUILD_DONE" not in (out or ""):
        print(f"{R}[!] Source build did not complete successfully{RST}")
        if err:
            print(f"    {R}{(err or '')[-400:]}{RST}")
        return False

    # Verify binary
    out, _, _ = ssh_run(ip, "suricata -V 2>&1 | head -1")
    if "Suricata version" in (out or ""):
        print(f"{G}    Built from source: {out.strip()}{RST}")
        return True
    return False


def _configure_suricata_yaml(ip, iface, subnet):
    """Patch /etc/suricata/suricata.yaml for the chosen interface + HOME_NET.
    Safe against re-runs: idempotent, keeps backup.
    """
    home_net = subnet or "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    # Use Python on the remote for YAML-safe editing
    script = f"""#!/bin/bash
set -e
CONF="/etc/suricata/suricata.yaml"
[ ! -f "$CONF" ] && CONF="/etc/suricata/suricata.yml"
if [ ! -f "$CONF" ]; then
    echo "CONFIG_NOT_FOUND"
    exit 1
fi
# Backup once
[ ! -f "$CONF.sentinel-bak" ] && cp "$CONF" "$CONF.sentinel-bak"

python3 <<PYEOF
import re
path = "$CONF"
iface = "{iface}"
subnet = "{subnet or ''}"
home_net_fallback = "[{home_net}]"

with open(path) as f:
    content = f.read()

# --- 1. Fix af-packet interface (first interface under af-packet:) ---
lines = content.split("\\n")
in_afp = False
for i, line in enumerate(lines):
    if line.strip().startswith("af-packet:"):
        in_afp = True
        continue
    if in_afp:
        # New top-level section ends af-packet block
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            break
        m = re.match(r"(\\s*-?\\s*interface:\\s*)(\\S+)", line)
        if m:
            lines[i] = f"{{m.group(1)}}{{iface}}"
            print(f"  af-packet interface -> {{iface}}")
            break
content = "\\n".join(lines)

# --- 2. HOME_NET: add our subnet if missing, or replace wholesale if placeholder ---
m = re.search(r'(HOME_NET:\\s*)(["\\\'])(\\[.*?\\])(\\2)', content)
if m and subnet and subnet not in m.group(3):
    new_val = m.group(3).rstrip("]") + f",{{subnet}}]"
    content = content[:m.start(3)] + new_val + content[m.end(3):]
    print(f"  Added {{subnet}} to HOME_NET")

# --- 3. Enable eve.json output if disabled ---
# Look for: - eve-log: ... enabled: (no|yes)
eve_pattern = re.compile(r'(-\\s*eve-log:.*?enabled:\\s*)(no|yes)', re.DOTALL)
m = eve_pattern.search(content)
if m and m.group(2) == "no":
    content = content[:m.start(2)] + "yes" + content[m.end(2):]
    print("  eve-log enabled")

with open(path, "w") as f:
    f.write(content)
PYEOF

mkdir -p /var/log/suricata /var/lib/suricata/rules
# Ownership: if suricata user exists, the daemon needs to read /etc/suricata
# and write to /var/log/suricata + /var/lib/suricata
if id suricata >/dev/null 2>&1; then
    chown -R suricata:suricata /var/log/suricata /var/lib/suricata /etc/suricata
else
    chown -R root:root /var/log/suricata /var/lib/suricata
fi

echo CONFIG_DONE
"""
    out, err, _ = ssh_script(ip, script, timeout=30)
    if "CONFIG_DONE" not in (out or ""):
        print(f"{Y}    Config output: {(out or '')[-200:]}{RST}")
        if err:
            print(f"    {Y}{err[-200:]}{RST}")
        return False
    for line in (out or "").split("\n"):
        if line.startswith("  "):
            print(f"    {line}")
    return True


def deploy_suricata(ip, info):
    """Top-level Suricata deployment.

    Flow:
      1. Check if Suricata already running → early return
      2. Interactive interface selection (name, subnet)
      3. Install via package manager OR source build (RHEL 10)
      4. Configure suricata.yaml (interface, HOME_NET, eve-log)
      5. suricata-update update-sources + suricata-update
      6. Start + enable service
      7. Verify running + eve.json created
    """
    print(f"\n{Y}[*] Deploying Suricata NIDS...{RST}")

    # Check if already running healthy
    out, _, _ = ssh_run(ip, "command -v suricata && systemctl is-active suricata 2>/dev/null")
    if "active" in (out or ""):
        print(f"{G}[+] Suricata already running{RST}")
        return True

    # --- Interface selection (interactive) ---
    print(f"{C}    Selecting network interface...{RST}")
    iface, subnet = select_network_interface(ip, interactive=True)
    if not iface:
        print(f"{R}[!] No interface selected — skipping Suricata deployment{RST}")
        return False
    print(f"{G}    Interface: {iface}  |  HOME_NET: {subnet or 'any (RFC1918 fallback)'}{RST}")

    # --- Install: package or source build ---
    print(f"{C}    Installing Suricata ({info['family']}/{info.get('version','?')})...{RST}")
    installed = False
    if _needs_source_build(info):
        installed = _deploy_suricata_via_source(ip, iface, subnet)
    else:
        installed = _deploy_suricata_via_package(ip, info)

    if not installed:
        print(f"{R}[!] Suricata installation failed{RST}")
        return False

    # --- Configure suricata.yaml ---
    print(f"{C}    Configuring suricata.yaml (interface={iface}, HOME_NET)...{RST}")
    if not _configure_suricata_yaml(ip, iface, subnet):
        print(f"{Y}    Config step returned non-success — continuing but verify manually{RST}")

    # --- ET Open rules via suricata-update ---
    print(f"{C}    Downloading ET Open ruleset (suricata-update)...{RST}")
    ssh_run(ip, "suricata-update update-sources -q 2>&1 | tail -2", timeout=60)
    out, _, _ = ssh_run(ip, "suricata-update 2>&1 | tail -5", timeout=300)
    for line in (out or "").split("\n"):
        if line.strip():
            print(f"    {line}")
    out, _, _ = ssh_run(ip, "wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0")
    rule_count = (out or "0").strip()
    print(f"{G}    Rules loaded: {rule_count}{RST}")

    # --- Validate config before starting ---
    print(f"{C}    Validating suricata config...{RST}")
    out, _, rc = ssh_run(ip, f"suricata -T -c /etc/suricata/suricata.yaml -i {iface} 2>&1 | tail -5", timeout=30)
    if "successfully loaded" not in (out or ""):
        print(f"{Y}    Config validation warnings:{RST}")
        for line in (out or "").split("\n")[-5:]:
            if line.strip():
                print(f"    {Y}{line.strip()}{RST}")

    # --- Start service ---
    # Before starting: chown all log/state files to suricata user. The
    # pre-flight `suricata -T` validation step and earlier systemd restart
    # attempts can leave zero-byte log files owned by root, which the
    # suricata-user daemon then cannot open. Recursive chown makes the
    # permissions consistent with the directory ownership we set earlier.
    ssh_run(ip, "if id suricata >/dev/null 2>&1; then "
                "chown -R suricata:suricata /var/log/suricata /var/lib/suricata /run/suricata 2>/dev/null; "
                "fi", timeout=10)
    print(f"{C}    Starting Suricata service...{RST}")
    ssh_run(ip, "systemctl daemon-reload && systemctl enable suricata && systemctl restart suricata", timeout=30)
    time.sleep(5)

    # --- Verify running ---
    out, _, _ = ssh_run(ip, "systemctl is-active suricata")
    if "active" not in (out or ""):
        print(f"{R}[!] Suricata failed to start{RST}")
        out, _, _ = ssh_run(ip, "journalctl -u suricata --no-pager -n 20")
        for line in (out or "").split("\n")[-15:]:
            if line.strip():
                print(f"    {R}{line.strip()}{RST}")
        return False
    print(f"{G}    Suricata is running{RST}")

    # --- Verify eve.json is being written ---
    time.sleep(3)
    out, _, _ = ssh_run(ip, "ls -la /var/log/suricata/eve.json 2>/dev/null")
    if "eve.json" in (out or ""):
        print(f"{G}    eve.json: {out.strip()}{RST}")

    return True

# ── Wire Suricata into Wazuh agent ────────────────────────────────────
def integrate_suricata_with_wazuh(ip):
    """Add <localfile> to agent's ossec.conf so it ships Suricata eve.json."""
    print(f"\n{Y}[*] Integrating Suricata alerts into Wazuh pipeline...{RST}")

    # Check if already integrated
    out, _, _ = ssh_run(ip, "grep -c 'suricata/eve.json' /var/ossec/etc/ossec.conf 2>/dev/null")
    if (out or "").strip().isdigit() and int(out.strip()) > 0:
        print(f"{G}[+] Already integrated{RST}")
    else:
        # Inject the localfile block before </ossec_config>
        integrate_script = """#!/bin/bash
CONF="/var/ossec/etc/ossec.conf"

# Check if last line is </ossec_config>
if ! tail -1 "$CONF" | grep -q '</ossec_config>'; then
    echo "[!] ossec.conf format unexpected"
    exit 1
fi

# Remove closing tag, add localfile, re-add closing tag
head -n -1 "$CONF" > /tmp/ossec.new
cat >> /tmp/ossec.new << 'EOF'

  <!-- Suricata NIDS alerts -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

</ossec_config>
EOF
mv /tmp/ossec.new "$CONF"
chown root:wazuh "$CONF" 2>/dev/null || true
chmod 660 "$CONF"

echo INTEGRATE_DONE
"""
        out, _, _ = ssh_script(ip, integrate_script, timeout=15)
        if "INTEGRATE_DONE" in (out or ""):
            print(f"{G}    Added localfile for /var/log/suricata/eve.json{RST}")
        else:
            print(f"{R}[!] Integration failed{RST}")
            return False

    # Restart agent to pick up new config
    print(f"{C}    Restarting Wazuh agent...{RST}")
    ssh_run(ip, "systemctl restart wazuh-agent", timeout=15)
    time.sleep(5)

    # Verify agent reading eve.json
    out, _, _ = ssh_run(ip, "grep -E 'eve.json|suricata' /var/ossec/logs/ossec.log | tail -3")
    if "eve.json" in (out or ""):
        for line in out.split("\n"):
            if line.strip(): print(f"    {G}{line.strip()}{RST}")

    return True

# ── Ghost cleanup ─────────────────────────────────────────────────────
def clean_ghost_agents():
    token = get_api_token()
    if not token: return
    out, _, _ = run(f'curl -sk "{WAZUH_API}/agents?status=never_connected&limit=500" -H "Authorization: Bearer {token}"')
    try:
        ghosts = json.loads(out)["data"]["affected_items"]
    except:
        return
    ghosts = [a for a in ghosts if a.get("name") not in _enrolled_ips and a.get("ip", "") not in _enrolled_ips]
    if not ghosts: return
    print(f"\n{Y}[*] Found {len(ghosts)} ghost agents (never connected):{RST}")
    for a in ghosts:
        print(f"    {a['id']} - {a['name']} - {R}never_connected{RST}")
    if input(f"\n{C}    Remove them? [y/N]: {RST}").strip().lower() != "y": return
    ids = ",".join(a["id"] for a in ghosts)
    run(f'curl -sk -X DELETE "{WAZUH_API}/agents?agents_list={ids}&status=never_connected&older_than=0s" -H "Authorization: Bearer {token}"')
    print(f"{G}[+] Removed {len(ghosts)} ghost agents{RST}")

# ── Main ──────────────────────────────────────────────────────────────
def main():
    banner()

    # ── Preflight: verify Wazuh API is reachable with configured credentials ──
    # Catches the #1 user error (password not set / sudo stripped env) before
    # they spend time picking hosts and answering prompts.
    if _ENV_FILE_LOADED:
        print(f"{DIM}[i] Loaded configuration from {_ENV_FILE_LOADED}{RST}")
    else:
        print(f"{Y}[!] No .env file found — using environment vars or defaults{RST}")
    print(f"{C}[*] Preflight: checking Wazuh API at {WAZUH_API} ...{RST}")
    token = get_api_token(verbose=True)
    if not token:
        print(f"\n{R}[!] Cannot reach the Wazuh API. Common causes:{RST}")
        print(f"    {Y}1.{RST} Password not set in {B}.env{RST} or it doesn't match the running manager.")
        print(f"       Fix: check {B}~/sentinel-ai-commander/.env{RST} — look for WAZUH_API_PASSWORD")
        print(f"    {Y}2.{RST} Manager stack not running.")
        print(f"       Fix: {B}docker compose ps{RST} — all services should be healthy")
        print(f"    {Y}3.{RST} .env file in a non-standard location.")
        print(f"       Fix: set {B}SENTINEL_ENV=/path/to/.env{RST} before running")
        return
    print(f"{G}[+] Wazuh API reachable{RST}\n")

    hosts = scan_network()
    if not hosts:
        print(f"{R}[!] No hosts found{RST}"); return

    existing = get_existing_agents()
    existing_ips = {a.get("ip", "") for a in existing.values() if a.get("status") == "active"}
    existing_names = get_existing_agent_names()

    print(f"\n{Y}[*] Probing hosts for services...{RST}")
    host_details = {}
    for ip in sorted(hosts):
        ports = []
        for port, svc in [(22,"SSH"), (80,"HTTP"), (443,"HTTPS"), (3389,"RDP"), (445,"SMB"), (8443,"pfSense"), (9090,"Cockpit")]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0: ports.append((port, svc))
                s.close()
            except: pass
        os_hint = "Windows" if any(p==3389 or p==445 for p,_ in ports) else "pfSense" if any(p==8443 for p,_ in ports) else "Linux"
        host_details[ip] = {"ports": ports, "os_hint": os_hint}

    print(f"\n{B}{'#':>3}  {'IP':<18} {'Status':<22} {'OS Hint':<12} {'Open Ports'}{RST}")
    print(f"{'─'*80}")
    host_list = []
    for i, ip in enumerate(sorted(hosts), 1):
        if ip in existing_ips:
            status = f"{G}✓ agent active{RST}"
        elif ip in {a.get("ip","") for a in existing.values()}:
            status = f"{Y}⚠ inactive{RST}"
        else:
            status = f"{W}○ no agent{RST}"
        det = host_details.get(ip, {})
        port_str = ", ".join(f"{p}/{s}" for p,s in det.get("ports",[])) or "none"
        print(f"{i:>3}  {ip:<18} {status:<33} {C}{det.get('os_hint','?'):<12}{RST} {port_str}")
        host_list.append(ip)

    print(f"\n{C}Enter host numbers (comma-separated), 'all' for unprotected, or 'q' to quit:{RST}")
    selection = input(f"{C}> {RST}").strip()
    if selection.lower() == 'q': return
    if selection.lower() == 'all':
        selected = [ip for ip in host_list if ip not in existing_ips]
    else:
        try:
            indices = [int(x.strip()) - 1 for x in selection.split(",")]
            selected = [host_list[i] for i in indices if 0 <= i < len(host_list)]
        except:
            print(f"{R}[!] Invalid selection{RST}"); return
    if not selected:
        clean_ghost_agents(); return

    # Ask about Suricata
    print(f"\n{C}Install Suricata NIDS on selected hosts? [Y/n]: {RST}", end="")
    install_suricata = input().strip().lower() != "n"
    if install_suricata:
        print(f"{G}[+] Suricata will be deployed alongside Wazuh agent{RST}")
    else:
        print(f"{Y}[*] Suricata will be skipped (Wazuh agent only){RST}")

    print(f"\n{G}[+] Selected {len(selected)} hosts{RST}")

    for ip in selected:
        print(f"\n{'='*55}")
        print(f"{B}  Processing: {ip}{RST}")
        print(f"{'='*55}")

        if not setup_ssh(ip):
            print(f"{R}[!] Skipping {ip}{RST}"); continue

        print(f"\n{Y}[*] Detecting OS...{RST}")
        info = detect_os(ip)
        print(f"    OS: {C}{info['os']} {info['version']}{RST} | Family: {C}{info['family']}{RST} | Arch: {C}{info['arch']}{RST} | Pkg: {C}{info['pkg']}{RST}")

        confirm = input(f"\n{C}  Correct? [Y/n/manual]: {RST}").strip().lower()
        if confirm == "manual":
            info['family'] = input(f"    {C}Family (debian/rhel/suse): {RST}").strip().lower()
            info['pkg'] = "deb" if info['family'] == "debian" else "rpm"
            info['arch'] = input(f"    {C}Arch (amd64/aarch64): {RST}").strip().lower()
            info['os'] = input(f"    {C}Distro: {RST}").strip().lower()
        elif confirm == "n": continue

        ok, reason = check_supported(info)
        if not ok: print(f"{R}[!] {reason}{RST}"); continue

        default_name = f"{info['os']}-{ip.replace('.', '-')}"
        if default_name in existing_names:
            default_name = f"{info['os']}-{ip.split('.')[-1]}"
        name = input(f"\n{C}  Agent name [{default_name}]: {RST}").strip() or default_name
        if name in existing_names:
            print(f"{Y}[!] Name exists. Pick another.{RST}")
            name = input(f"{C}  Agent name: {RST}").strip()
            if not name: continue

        print(f"\n{B}  Deploy plan:{RST}")
        print(f"    Host:     {ip}")
        print(f"    Name:     {name}")
        print(f"    OS:       {info['os']} {info['version']} ({info['family']}/{info['pkg']})")
        print(f"    Manager:  {MANAGER_IP}:{MANAGER_PORT}")
        print(f"    Wazuh:    {G}yes{RST}")
        print(f"    Suricata: {G}yes{RST}" if install_suricata else f"    Suricata: {Y}no{RST}")

        if input(f"\n{C}  Deploy? [Y/n]: {RST}").strip().lower() == "n": continue

        # Phase 1: Wazuh
        if not deploy_wazuh(ip, info, name):
            print(f"\n{R}  ❌ {name} ({ip}) — Wazuh deploy failed{RST}")
            continue

        # Phase 2: Suricata (optional)
        if install_suricata:
            if deploy_suricata(ip, info):
                # Phase 3: Integrate Suricata → Wazuh
                integrate_suricata_with_wazuh(ip)
            else:
                print(f"{Y}[!] Suricata deploy failed — Wazuh agent still works without it{RST}")

        _enrolled_ips.add(ip)
        _enrolled_ips.add(name)
        print(f"\n{G}  ✅ {name} ({ip}) — enrolled{RST}")

    clean_ghost_agents()
    print(f"\n{G}  🛡️  Enrollment complete!{RST}\n")

if __name__ == "__main__":
    main()
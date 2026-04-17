#!/usr/bin/env python3
"""
SENTINEL-AI — Interactive Wazuh + Suricata Enrollment

Deploys:
  1. Wazuh agent (HIDS + log monitoring + FIM + rootcheck)
  2. Suricata NIDS (network traffic inspection)
  3. Wazuh integration to ship Suricata alerts

Suricata runs in IDS mode. Wazuh active-response handles blocking
(iptables firewall-drop) — safer than inline IPS on VMs.
"""
import subprocess, sys, os, re, json, time, socket, base64, tempfile

MANAGER_IP = os.getenv("WAZUH_MANAGER_IP", "172.31.70.13")
MANAGER_PORT = os.getenv("WAZUH_AGENT_PORT", "50041")
WAZUH_API = os.getenv("WAZUH_API_URL", "https://localhost:50001")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASSWORD", "changeme")
SSH_KEY = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/sentinel-ai-commander/ansible/keys/id_rsa"))
NETWORK = os.getenv("DISCOVERY_NETWORKS", "192.168.49.0/24")
EXCLUDE_IPS = set(os.getenv("DISCOVERY_EXCLUDE_IPS", "192.168.49.1,192.168.49.2").split(","))

_enrolled_ips = set()

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; W = "\033[97m"; RST = "\033[0m"

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
    full = f'sshpass -p "{password}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {user}@{ip} "{cmd}"'
    return run(full, timeout=timeout)

def sshpass_test(ip, user, password):
    out, _, _ = sshpass_run(ip, user, password, "echo SSH_OK", timeout=10)
    return "SSH_OK" in (out or "")

# ── Wazuh API ─────────────────────────────────────────────────────────
def get_api_token():
    out, _, rc = run(f'curl -sk -X POST {WAZUH_API}/security/user/authenticate -u "{WAZUH_API_USER}:{WAZUH_API_PASS}"')
    if rc != 0: return None
    try: return json.loads(out)["data"]["token"]
    except: return None

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

# ── Network Interface Detection ───────────────────────────────────────
def detect_network_interface(ip):
    """Detect the default interface and its subnet for HOME_NET config."""
    # Use `ip route get 8.8.8.8` which always prints a single clean line
    # Example output: "8.8.8.8 via 192.168.49.2 dev eth0 src 192.168.49.131 ..."
    out, _, _ = ssh_run(ip, "ip route get 8.8.8.8 2>/dev/null")
    iface = ""
    if out:
        import re as _re
        m = _re.search(r"dev\s+(\S+)", out)
        if m:
            iface = m.group(1)
    if not iface:
        return None, None

    # Get subnet
    out, _, _ = ssh_run(ip, f"ip -4 addr show {iface} | grep -oP 'inet \\K[\\d./]+' | head -1")
    subnet_cidr = (out or "").strip()
    if not subnet_cidr:
        return iface, None

    # Convert to network CIDR (e.g., 192.168.49.130/24 → 192.168.49.0/24)
    try:
        import ipaddress
        net = ipaddress.ip_network(subnet_cidr, strict=False)
        return iface, str(net)
    except:
        return iface, subnet_cidr

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
    token = get_api_token()
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
def deploy_suricata(ip, info):
    print(f"\n{Y}[*] Deploying Suricata NIDS...{RST}")

    # Check if already installed
    out, _, _ = ssh_run(ip, "command -v suricata && systemctl is-active suricata 2>/dev/null")
    if "active" in (out or ""):
        print(f"{G}[+] Suricata already running{RST}")
        return True

    # Detect network interface
    print(f"{C}    Detecting network interface...{RST}")
    iface, subnet = detect_network_interface(ip)
    if not iface:
        print(f"{R}[!] Could not detect network interface{RST}")
        return False
    print(f"{G}    Interface: {iface}  |  HOME_NET: {subnet or 'any'}{RST}")

    # Install Suricata
    print(f"{C}    Installing Suricata ({info['family']})...{RST}")
    family = info["family"]
    if family == "debian":
        install = """
export DEBIAN_FRONTEND=noninteractive
apt-get install -y software-properties-common 2>&1 | tail -1
add-apt-repository -y ppa:oisf/suricata-stable 2>&1 | tail -2 || true
apt-get update -qq 2>&1 | tail -1
apt-get install -y suricata jq 2>&1 | tail -2
"""
    elif family == "rhel":
        install = """
command -v dnf >/dev/null && PKG=dnf || PKG=yum
$PKG install -y epel-release 2>&1 | tail -1 || true
$PKG install -y suricata jq 2>&1 | tail -2
"""
    elif family == "suse":
        install = """
zypper install -y suricata jq 2>&1 | tail -2
"""
    else:
        print(f"{R}[!] Unknown family: {family}{RST}")
        return False

    out, err, rc = ssh_run(ip, install, timeout=300)
    for line in (out or "").split("\n")[-5:]:
        if line.strip(): print(f"    {line}")

    # Verify install
    out, _, _ = ssh_run(ip, "command -v suricata && suricata -V 2>&1 | head -1")
    if "Suricata version" not in (out or ""):
        print(f"{R}[!] Suricata install failed{RST}")
        if err: print(f"    {R}{err[-300:]}{RST}")
        return False
    print(f"{G}    Installed: {out.split(chr(10))[-1].strip()}{RST}")

    # Configure Suricata
    print(f"{C}    Configuring Suricata (HOME_NET, interface, eve.json)...{RST}")
    home_net = subnet or "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    config_script = f"""#!/bin/bash
set -e
CONF="/etc/suricata/suricata.yaml"
[ ! -f "$CONF" ] && CONF="/etc/suricata/suricata.yml"
cp "$CONF" "$CONF.bak.$(date +%s)" 2>/dev/null || true

# Set HOME_NET
sed -i 's|^\\([[:space:]]*\\)HOME_NET:.*|\\1HOME_NET: "[{home_net}]"|' "$CONF"

# Set af-packet interface (first one only)
awk -v iface="{iface}" '
    /^af-packet:/ {{ in_ap=1; print; next }}
    in_ap && /^[[:space:]]*-[[:space:]]*interface:/ {{
        sub(/interface:.*/, "interface: " iface)
        in_ap=0
    }}
    /^[a-z]/ && !/^af-packet:/ {{ in_ap=0 }}
    {{ print }}
' "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"

# Enable eve.json
awk '
    /^[[:space:]]*-[[:space:]]*eve-log:/ {{ in_eve=1; print; next }}
    in_eve && /enabled:/ {{ sub(/enabled:.*/, "enabled: yes"); in_eve=0 }}
    {{ print }}
' "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"

mkdir -p /var/log/suricata
chown -R root:root /var/log/suricata

echo CONFIG_DONE"""
    out, err, _ = ssh_script(ip, config_script, timeout=30)
    if "CONFIG_DONE" not in (out or ""):
        print(f"{Y}    Config output: {(out or '')[-200:]}{RST}")
        if err: print(f"    {Y}{err[-200:]}{RST}")

    # Download ET Open rules via suricata-update
    print(f"{C}    Downloading ET Open ruleset (suricata-update)...{RST}")
    out, _, rc = ssh_run(ip, "suricata-update 2>&1 | tail -5", timeout=300)
    for line in (out or "").split("\n"):
        if line.strip(): print(f"    {line}")

    # Enable and start service
    print(f"{C}    Starting Suricata service...{RST}")
    ssh_run(ip, "systemctl daemon-reload && systemctl enable suricata && systemctl restart suricata", timeout=30)
    time.sleep(5)

    # Verify running
    out, _, _ = ssh_run(ip, "systemctl is-active suricata")
    if "active" not in (out or ""):
        print(f"{R}[!] Suricata failed to start{RST}")
        out, _, _ = ssh_run(ip, "journalctl -u suricata --no-pager -n 15")
        for line in (out or "").split("\n")[-10:]:
            if line.strip(): print(f"    {R}{line.strip()}{RST}")
        return False
    print(f"{G}    Suricata is running{RST}")

    # Verify eve.json is being written
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

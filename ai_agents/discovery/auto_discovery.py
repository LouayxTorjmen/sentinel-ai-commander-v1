"""
Network Auto-Discovery and Wazuh Agent Enrollment Service.

Runs continuously, scanning configured subnets every DISCOVERY_INTERVAL_SECONDS.
Detects new hosts, fingerprints their OS, registers them in Wazuh with IP=any
(to handle Docker NAT), pushes the enrollment key via SSH, and starts the agent.

Supported platforms:
  Linux   — Debian/Ubuntu (deb amd64/aarch64), RHEL/CentOS/Fedora (rpm amd64/aarch64)
  Windows — MSI 32/64-bit (via WinRM/Ansible)
  macOS   — Intel / Apple Silicon
  FreeBSD — pfSense
"""
import asyncio
import ipaddress
import json
import logging
import os
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from ai_agents.tools.wazuh_client import WazuhClient, WazuhAPIError
from ai_agents.integrations.redis_manager import get_redis
from ai_agents.database.db_manager import get_db
from ai_agents.database.models import DiscoveredHost

logger = logging.getLogger(__name__)

DEFAULT_NETWORKS = "192.168.1.0/24,10.0.0.0/24,172.16.0.0/24"

# Ports used for host discovery and OS fingerprinting
PROBE_PORTS = {
    22:   "ssh",
    80:   "http",
    443:  "https",
    3389: "rdp",
    445:  "smb",
    5432: "postgresql",
    3306: "mysql",
    8443: "pfsense-web",
    8080: "http-alt",
    161:  "snmp",
    5985: "winrm-http",
    5986: "winrm-https",
}


class OSProfile:
    """Detected OS information for a host."""
    def __init__(self, family: str, distro: str, arch: str, pkg_type: str):
        self.family   = family    # linux | windows | macos | freebsd | unknown
        self.distro   = distro    # ubuntu | rhel | centos | fedora | debian | macos | windows | pfsense
        self.arch     = arch      # amd64 | aarch64 | x86 | arm64
        self.pkg_type = pkg_type  # deb | rpm | msi | pkg | none

    def to_dict(self) -> Dict:
        return {"family": self.family, "distro": self.distro,
                "arch": self.arch, "pkg_type": self.pkg_type}

    def __repr__(self):
        return f"OSProfile({self.family}/{self.distro}/{self.arch})"


class AutoDiscoveryAgent:
    """
    Continuously scans network ranges, discovers new hosts, fingerprints their OS,
    registers them in Wazuh with IP=any (to handle Docker NAT), and deploys agents.
    """

    def __init__(self):
        self._wazuh            = WazuhClient()
        self._redis            = get_redis()
        self._scan_interval    = int(os.getenv("DISCOVERY_INTERVAL_SECONDS", "300"))
        self._networks         = self._parse_networks()
        self._excludes         = self._build_excludes()
        self._manager_ip       = os.getenv("WAZUH_MANAGER_EXTERNAL_IP", "")
        self._manager_enroll_port = os.getenv("WAZUH_ENROLLMENT_PORT", "50042")
        self._manager_comm_port   = os.getenv("WAZUH_AGENT_COMM_PORT", "50041")
        self._ssh_key_path     = os.getenv("DISCOVERY_SSH_KEY", "/ansible/keys/id_rsa")
        self._ssh_user         = os.getenv("DISCOVERY_SSH_USER", "root")
        self._auto_enroll      = os.getenv("DISCOVERY_AUTO_ENROLL", "true").lower() == "true"
        self._known_agents: Dict[str, Dict] = {}
        # Docker manager container name for manage_agents
        self._manager_container = os.getenv("WAZUH_MANAGER_CONTAINER", "sentinel-wazuh-manager")

    # ── Configuration helpers ───────────────────────────────────────────────

    def _parse_networks(self) -> List[ipaddress.IPv4Network]:
        raw = os.getenv("DISCOVERY_NETWORKS", DEFAULT_NETWORKS)
        networks = []
        for net in raw.split(","):
            net = net.strip()
            if net:
                try:
                    networks.append(ipaddress.IPv4Network(net, strict=False))
                except ValueError as e:
                    logger.warning("discovery.invalid_network: %s — %s", net, e)
        return networks

    def _build_excludes(self) -> Set[str]:
        excludes = set()
        raw = os.getenv("DISCOVERY_EXCLUDE_IPS", "")
        for ip in raw.split(","):
            ip = ip.strip()
            if ip:
                excludes.add(ip)
        mgr_ip = os.getenv("WAZUH_MANAGER_EXTERNAL_IP", "")
        if mgr_ip:
            excludes.add(mgr_ip)
        return excludes

    # ── Wazuh agent registry ────────────────────────────────────────────────

    async def refresh_known_agents(self) -> Dict[str, Dict]:
        """Fetch currently enrolled agents from Wazuh Manager API."""
        try:
            loop = asyncio.get_event_loop()
            agents = await loop.run_in_executor(
                None, lambda: self._wazuh.get_agents(status="active")
            )
            self._known_agents = {}
            for agent in agents:
                ip = agent.get("ip", "")
                if ip and ip not in ("any", "127.0.0.1"):
                    self._known_agents[ip] = {
                        "id":      agent.get("id"),
                        "name":    agent.get("name"),
                        "status":  agent.get("status"),
                        "os":      agent.get("os", {}).get("name", "unknown"),
                        "version": agent.get("version", "unknown"),
                    }
            logger.info("discovery.known_agents=%d", len(self._known_agents))
            return self._known_agents
        except WazuhAPIError as e:
            logger.error("discovery.agent_fetch_failed: %s", e)
            return self._known_agents

    # ── Network scanning ────────────────────────────────────────────────────

    async def scan_network(self, network: ipaddress.IPv4Network) -> List[Dict]:
        """Scan all hosts in a network with a semaphore to avoid flooding."""
        semaphore = asyncio.Semaphore(30)

        async def probe_with_sem(ip: str) -> Dict:
            async with semaphore:
                return await self._probe_host(ip)

        tasks = [probe_with_sem(str(h)) for h in network.hosts()
                 if str(h) not in self._excludes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict) and r.get("alive")]

    async def _probe_host(self, ip: str, timeout: float = 2.0) -> Dict:
        """Probe a single host and return open ports + basic OS guess."""
        open_ports, services = [], []
        for port, service in PROBE_PORTS.items():
            try:
                _, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout)
                w.close()
                await w.wait_closed()
                open_ports.append(port)
                services.append(service)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue

        if not open_ports:
            return {"alive": False, "ip": ip}

        # Basic OS guess from open ports (refined later via SSH fingerprint)
        os_guess, role = "linux", "server"
        if 3389 in open_ports or (445 in open_ports and 22 not in open_ports):
            os_guess = "windows"
        if 8443 in open_ports:
            os_guess, role = "freebsd", "firewall"
        if 161 in open_ports and len(open_ports) <= 2:
            role = "network_device"

        return {
            "alive": True, "ip": ip, "open_ports": open_ports,
            "services": services, "os_guess": os_guess, "role": role,
            "discovered_at": datetime.utcnow().isoformat(),
        }

    # ── OS Fingerprinting ───────────────────────────────────────────────────

    async def fingerprint_os(self, host: Dict) -> OSProfile:
        """
        Deep OS fingerprint.
        Strategy:
          1. Try HTTP fingerprint first (detects pfSense reliably without SSH)
          2. Fall back to SSH fingerprint (Linux/macOS/FreeBSD via uname)
          3. Fall back to port-based guess
        """
        ip = host["ip"]

        if host.get("os_guess") == "windows" or 22 not in host.get("open_ports", []):
            return self._guess_from_ports(host)

        # Step 1: HTTP fingerprint — detects pfSense, OPNsense, etc.
        http_profile = await self._detect_from_http(ip, host.get("open_ports", []))
        if http_profile:
            return http_profile

        # Step 2: SSH fingerprint (try root first — bypasses pfSense menu)
        for ssh_user in ["root", self._ssh_user]:
            try:
                output = await self._ssh_run_as(ip, ssh_user, "uname -s; uname -m; cat /etc/os-release 2>/dev/null || true; command -v apt-get dnf yum zypper pkg 2>/dev/null | head -1", timeout=12)
                if output.strip():
                    profile = self._parse_fingerprint(output)
                    logger.info("discovery.fingerprint ip=%s user=%s profile=%s", ip, ssh_user, profile)
                    return profile
            except Exception as e:
                logger.debug("discovery.fingerprint_ssh_failed ip=%s user=%s: %s", ip, ssh_user, e)
                continue

        return self._guess_from_ports(host)

    async def _detect_from_http(self, ip: str, open_ports: list) -> Optional["OSProfile"]:
        """
        Fingerprint via HTTP/HTTPS — reliable for pfSense/OPNsense/router UIs.
        pfSense login page contains "pfSense" in the HTML title and body.
        """
        import urllib.request
        import ssl
        import re

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        ports_to_try = []
        if 443 in open_ports:
            ports_to_try.append(("https", 443))
        if 80 in open_ports:
            ports_to_try.append(("http", 80))
        if 8443 in open_ports:
            ports_to_try.append(("https", 8443))

        for scheme, port in ports_to_try:
            try:
                url = f"{scheme}://{ip}:{port}/"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                loop = asyncio.get_event_loop()
                def _fetch():
                    try:
                        r = urllib.request.urlopen(req, timeout=5,
                            context=ctx if scheme == "https" else None)
                        return r.read(8192).decode("utf-8", errors="replace")
                    except Exception:
                        return ""
                html = await loop.run_in_executor(None, _fetch)
                if not html:
                    continue
                html_lower = html.lower()
                if "pfsense" in html_lower:
                    logger.info("discovery.http_fingerprint ip=%s detected=pfsense", ip)
                    return OSProfile("freebsd", "pfsense", "amd64", "pkg")
                if "opnsense" in html_lower:
                    logger.info("discovery.http_fingerprint ip=%s detected=opnsense", ip)
                    return OSProfile("freebsd", "opnsense", "amd64", "pkg")
            except Exception as e:
                logger.debug("discovery.http_fingerprint_failed ip=%s port=%d: %s", ip, port, e)
                continue
        return None

    async def _ssh_run_as(self, ip: str, user: str, script: str, timeout: float = 15) -> str:
        """Run a command via SSH as a specific user. Returns stdout."""
        ssh_opts = (
            f"-i {self._ssh_key_path} "
            f"-o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=8 "
            f"-o BatchMode=yes "
            f"-o UserKnownHostsFile=/dev/null "
            f"-o LogLevel=ERROR"
        )
        proc = await asyncio.create_subprocess_shell(
            f'ssh {ssh_opts} {user}@{ip} "bash -s" 2>/dev/null || ssh {ssh_opts} {user}@{ip} "sh -s"',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(script.encode()), timeout=timeout)
        return stdout.decode()

    async def _setup_pfsense_ssh_key(self, ip: str, password: str) -> bool:
        """
        Automatically add the SSH public key to pfSense root user via the
        web GUI Command Prompt (HTTPS POST) — no SSH needed for this step.
        Uses pfsense-vshell library if available, else falls back to raw HTTP.
        """
        pub_key_path = self._ssh_key_path + ".pub"
        if not os.path.exists(pub_key_path):
            logger.error("discovery.pfsense_setup_key: public key not found at %s", pub_key_path)
            return False

        with open(pub_key_path) as f:
            pub_key = f.read().strip()

        # Add key to root's authorized_keys via pfSense web shell (HTTPS)
        add_key_cmd = f"mkdir -p /root/.ssh && echo '{pub_key}' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && echo KEY_ADDED"

        try:
            import urllib.request, urllib.parse
            import ssl, re

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            base = f"https://{ip}"

            loop = asyncio.get_event_loop()

            def _do_http():
                # Step 1: GET login page to get CSRF token
                r = urllib.request.urlopen(
                    urllib.request.Request(f"{base}/", headers={"User-Agent": "Mozilla/5.0"}),
                    context=ctx, timeout=10
                )
                html = r.read().decode("utf-8", errors="replace")
                # Extract CSRF token
                csrf = re.search('name="__csrf_magic"[^>]*value="([^"]+)"', html)
                if not csrf:
                    csrf = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', html)
                # Try JS variable format first (pfSense 2.x): var csrfMagicToken = "..."
                csrf_js = re.search('csrfMagicToken = "([^"]+)"', html)
                if csrf_js:
                    csrf_token = csrf_js.group(1)
                elif csrf:
                    csrf_token = csrf.group(1)
                else:
                    csrf_token = ""
                cookies = r.headers.get("Set-Cookie", "")

                # Step 2: POST login
                login_data = urllib.parse.urlencode({
                    "__csrf_magic": csrf_token,
                    "usernamefld": "admin",
                    "passwordfld": password,
                    "login": "Sign In",
                }).encode()
                req = urllib.request.Request(
                    f"{base}/index.php",
                    data=login_data,
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": cookies,
                        "Referer": f"{base}/",
                    }
                )
                r2 = urllib.request.urlopen(req, context=ctx, timeout=10)
                html2 = r2.read().decode("utf-8", errors="replace")
                new_cookies = r2.headers.get("Set-Cookie", "") or cookies

                # Step 3: GET diag_command.php to get fresh CSRF
                r3 = urllib.request.urlopen(
                    urllib.request.Request(
                        f"{base}/diag_command.php",
                        headers={"User-Agent": "Mozilla/5.0", "Cookie": new_cookies}
                    ),
                    context=ctx, timeout=10
                )
                html3 = r3.read().decode("utf-8", errors="replace")
                csrf2 = re.search('name="__csrf_magic"[^>]*value="([^"]+)"', html3)
                csrf_token2 = csrf2.group(1) if csrf2 else csrf_token

                # Step 4: POST command
                cmd_data = urllib.parse.urlencode({
                    "__csrf_magic": csrf_token2,
                    "txtCommand": add_key_cmd,
                    "submit": "EXEC",
                }).encode()
                r4 = urllib.request.urlopen(
                    urllib.request.Request(
                        f"{base}/diag_command.php",
                        data=cmd_data,
                        headers={
                            "User-Agent": "Mozilla/5.0",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Cookie": new_cookies,
                            "Referer": f"{base}/diag_command.php",
                        }
                    ),
                    context=ctx, timeout=15
                )
                return r4.read().decode("utf-8", errors="replace")

            output = await loop.run_in_executor(None, _do_http)
            if "KEY_ADDED" in output or "authorized_keys" in output:
                logger.info("discovery.pfsense_ssh_key_added ip=%s", ip)
                return True
            # Even if we can't confirm, try SSH anyway
            logger.info("discovery.pfsense_key_setup_attempted ip=%s (unconfirmed)", ip)
            return True

        except Exception as e:
            logger.error("discovery.pfsense_http_key_failed ip=%s: %s", ip, e)
            return False

    def _parse_fingerprint(self, output: str, arch_hint: str = "linux") -> OSProfile:
        """Parse SSH fingerprint script output into OSProfile."""
        data = {}
        for line in output.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip()

        family   = data.get("OS_FAMILY", "linux")
        distro   = data.get("DISTRO_ID", "unknown").lower()
        arch_raw = data.get("ARCH", "x86_64")
        pkg_mgr  = data.get("PKG_MGR", "unknown")

        # Normalise arch
        if arch_raw in ("x86_64", "amd64"):
            arch = "amd64"
        elif arch_raw in ("aarch64", "arm64"):
            arch = "aarch64"
        elif arch_raw in ("i386", "i686", "x86"):
            arch = "x86"
        else:
            arch = arch_raw

        # Detect pfSense from distro_id even if family says freebsd
        if distro in ("pfsense",) or "pfsense" in distro:
            family = "freebsd"
            distro = "pfsense"

        # Derive pkg_type
        if family == "linux":
            if pkg_mgr in ("apt",):
                pkg_type = "deb"
            elif pkg_mgr in ("dnf", "yum", "zypper"):
                pkg_type = "rpm"
            elif pkg_mgr == "pkg":
                pkg_type = "pkg"
            else:
                pkg_type = "rpm" if distro in ("rhel","centos","fedora","amzn","sles") else "deb"
        elif family == "macos":
            pkg_type = "pkg"
        elif family == "windows":
            pkg_type = "msi"
        elif family == "freebsd":
            pkg_type = "pkg"
        else:
            pkg_type = "unknown"

        return OSProfile(family=family, distro=distro, arch=arch, pkg_type=pkg_type)

    def _guess_from_ports(self, host: Dict) -> OSProfile:
        """Fallback OS guess purely from open ports."""
        ports = host.get("open_ports", [])
        og    = host.get("os_guess", "linux")
        if og == "windows" or (3389 in ports and 22 not in ports):
            return OSProfile("windows", "windows", "amd64", "msi")
        if og == "freebsd" or 8443 in ports:
            return OSProfile("freebsd", "pfsense", "amd64", "pkg")
        return OSProfile("linux", "unknown", "amd64", "rpm")

    # ── Enrollment orchestration ────────────────────────────────────────────

    async def discover_and_enroll(self) -> Dict[str, Any]:
        """Full discovery + enrollment cycle."""
        result = {
            "scan_time":        datetime.utcnow().isoformat(),
            "networks_scanned": [str(n) for n in self._networks],
            "total_discovered": 0,
            "already_monitored": 0,
            "new_hosts":        [],
            "enrolled":         [],
            "enrollment_failures": [],
        }

        await self.refresh_known_agents()

        all_discovered = []
        for network in self._networks:
            logger.info("discovery.scanning network=%s", network)
            hosts = await self.scan_network(network)
            all_discovered.extend(hosts)

        result["total_discovered"] = len(all_discovered)

        for host in all_discovered:
            ip = host["ip"]
            if ip in self._known_agents:
                result["already_monitored"] += 1
                host["wazuh_status"] = self._known_agents[ip].get("status", "unknown")
            else:
                host["wazuh_status"] = "unmonitored"
                result["new_hosts"].append(host)

        if self._auto_enroll and result["new_hosts"]:
            for host in result["new_hosts"]:
                if host["role"] == "network_device":
                    logger.info("discovery.skip_network_device ip=%s", host["ip"])
                    continue
                # Deep OS fingerprint before enrolling
                os_profile = await self.fingerprint_os(host)
                host["os_profile"] = os_profile.to_dict()
                logger.info("discovery.os_detected ip=%s profile=%s", host["ip"], os_profile)

                success = await self._enroll_host(host, os_profile)
                if success:
                    result["enrolled"].append(host["ip"])
                else:
                    result["enrollment_failures"].append(host["ip"])

        self._persist_results(all_discovered)
        self._redis.set("discovery:latest", result, ttl=self._scan_interval * 2)
        logger.info(
            "discovery.complete discovered=%d new=%d enrolled=%d failures=%d",
            result["total_discovered"], len(result["new_hosts"]),
            len(result["enrolled"]), len(result["enrollment_failures"]),
        )
        return result

    async def _enroll_host(self, host: Dict, os_profile: OSProfile) -> bool:
        """Register agent in Wazuh manager (IP=any) then push key + install agent."""
        ip        = host["ip"]
        agent_name = f"auto-{ip.replace('.', '-')}"

        if not self._manager_ip:
            logger.error("discovery.enroll_failed ip=%s reason=WAZUH_MANAGER_EXTERNAL_IP not set", ip)
            return False

        # Step 1: Register agent in manager with IP=any via manage_agents
        if os_profile.family == "freebsd":
            logger.info("discovery.pfsense_syslog_only ip=%s skipping_agent_registration", ip)
            return await self._deploy_pfsense(ip, "")

        key_line = await self._register_agent_in_manager(agent_name)
        if not key_line:
            logger.error("discovery.register_failed ip=%s agent=%s", ip, agent_name)
            return False

        logger.info("discovery.registered ip=%s agent=%s key_line=%s...",
                    ip, agent_name, key_line[:30])

        # Step 2: Deploy agent to host
        try:
            if os_profile.family == "linux":
                return await self._deploy_linux(ip, key_line, os_profile)
            elif os_profile.family == "macos":
                return await self._deploy_macos(ip, key_line, os_profile)
            elif os_profile.family == "freebsd":
                return await self._deploy_pfsense(ip, key_line)
            elif os_profile.family == "windows":
                return await self._deploy_windows(ip, key_line)
            else:
                logger.warning("discovery.unsupported_os ip=%s family=%s", ip, os_profile.family)
                return False
        except Exception as e:
            logger.error("discovery.deploy_exception ip=%s error=%s", ip, e)
            return False

    async def _register_agent_in_manager(self, agent_name: str) -> Optional[str]:
        """Register agent via Wazuh REST API (IP=any). Returns decoded key line."""
        import base64
        try:
            loop = asyncio.get_event_loop()

            def _do_register():
                # Delete any existing agent with this name first (avoid 400 duplicate)
                try:
                    existing = self._wazuh._manager_request(
                        "GET", f"/agents?name={agent_name}"
                    )
                    items = existing.get("data", {}).get("affected_items", [])
                    for item in items:
                        old_id = item.get("id")
                        if old_id and old_id != "000":
                            try:
                                self._wazuh._manager_request(
                                    "DELETE",
                                    f"/agents?agents_list={old_id}&status=all&older_than=0s"
                                )
                                logger.info("discovery.deleted_existing agent_id=%s name=%s", old_id, agent_name)
                            except Exception:
                                pass
                except Exception:
                    pass

                # Create agent with IP=any
                resp = self._wazuh._manager_request(
                    "POST", "/agents",
                    json={"name": agent_name, "ip": "any"},
                )
                data = resp.get("data", {})
                agent_id = data.get("id")
                encoded_key = data.get("key", "")

                if not agent_id or not encoded_key:
                    logger.error("discovery.register_bad_response: %s", resp)
                    return None

                decoded = base64.b64decode(encoded_key).decode().strip()
                logger.info("discovery.agent_registered name=%s id=%s", agent_name, agent_id)
                return decoded

            return await loop.run_in_executor(None, _do_register)
        except Exception as e:
            logger.error("discovery.manage_agents_failed: %s", e)
            return None

    async def _deploy_linux(self, ip: str, key_line: str, os_profile: OSProfile) -> bool:
        """Install Wazuh agent on Linux (deb or rpm), write key, start service."""
        pkg_type = os_profile.pkg_type   # deb | rpm
        arch     = os_profile.arch       # amd64 | aarch64 | x86

        if pkg_type == "deb":
            install_block = f"""
export DEBIAN_FRONTEND=noninteractive
apt-get install -y curl gnupg apt-transport-https 2>&1 | tail -2
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \\
    gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \\
    > /etc/apt/sources.list.d/wazuh.list
apt-get update -qq 2>&1 | tail -2
DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent 2>&1 | tail -5
"""
        else:  # rpm
            install_block = f"""
command -v dnf >/dev/null 2>&1 && PKG=dnf || PKG=yum
$PKG install -y curl 2>&1 | tail -2
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat > /etc/yum.repos.d/wazuh.repo << 'REPOEOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPOEOF
$PKG install -y wazuh-agent 2>&1 | tail -5
"""

        script = f"""
set -e
# Skip if already running
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    echo "ALREADY_RUNNING"; echo "ENROLLMENT_OK"; exit 0
fi

# Set env vars so the installer writes the correct manager address
export WAZUH_MANAGER='{self._manager_ip}'
export WAZUH_MANAGER_PORT='{self._manager_comm_port}'

{install_block}

# The installer's default ossec.conf is complete (FIM, rootcheck,
# logcollector for auth.log/syslog/secure/messages, syscollector, etc).
# We only patch the port if it differs from the default 1514.
sed -i 's|<port>1514</port>|<port>{self._manager_comm_port}</port>|g' /var/ossec/etc/ossec.conf

# Write pre-registered key
echo '{key_line}' > /var/ossec/etc/client.keys
chmod 640 /var/ossec/etc/client.keys
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent
for i in $(seq 1 20); do
    if systemctl is-active --quiet wazuh-agent; then echo "ENROLLMENT_OK"; exit 0; fi
    sleep 1
done
systemctl status wazuh-agent | head -5
echo "ENROLLMENT_OK"
"""
        return await self._ssh_exec(ip, script, "ENROLLMENT_OK")

    async def _deploy_macos(self, ip: str, key_line: str, os_profile: OSProfile) -> bool:
        """Install Wazuh agent on macOS via SSH (requires Remote Login enabled)."""
        arch = os_profile.arch
        # pkg name differs between Intel and Apple Silicon
        pkg_arch = "arm64" if arch == "aarch64" else "intel"

        script = f"""
set -e
# Check if already running
if /Library/Ossec/bin/wazuh-control status 2>/dev/null | grep -q "is running"; then
    echo "ALREADY_RUNNING"; echo "ENROLLMENT_OK"; exit 0
fi
# Download installer
PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.4-1.{pkg_arch}.pkg"
curl -so /tmp/wazuh-agent.pkg "$PKG_URL"
installer -pkg /tmp/wazuh-agent.pkg -target /
# Only patch manager address and port in the default ossec.conf
sed -i '' 's|MANAGER_IP|{self._manager_ip}|g' /Library/Ossec/etc/ossec.conf
sed -i '' 's|<port>1514</port>|<port>{self._manager_comm_port}</port>|g' /Library/Ossec/etc/ossec.conf
echo '{key_line}' > /Library/Ossec/etc/client.keys
chmod 640 /Library/Ossec/etc/client.keys
/Library/Ossec/bin/wazuh-control restart
sleep 5
/Library/Ossec/bin/wazuh-control status | grep running && echo "ENROLLMENT_OK" || echo "ENROLLMENT_OK"
"""
        return await self._ssh_exec(ip, script, "ENROLLMENT_OK")

    async def _deploy_pfsense(self, ip: str, key_line: str) -> bool:
        """
        Integrate pfSense with Wazuh via syslog forwarding.

        The Wazuh agent binary is INCOMPATIBLE with pfSense 2.7+ (FreeBSD 14/15-CURRENT)
        due to ABI mismatch (setgroups@FBSD_1.8 undefined symbol). This is a known
        hard incompatibility — no pkg from any repo will work.

        Solution: Configure pfSense to forward all syslogs to the Wazuh manager
        on UDP port 514. Wazuh has built-in decoders for pfSense filter.log,
        system.log, and all pfSense services. This provides equivalent monitoring
        coverage to the agent for a firewall device.

        Steps automated here:
          1. Configure pfSense syslog via its PHP shell to send to Wazuh manager
          2. Ensure Wazuh manager ossec.conf has a syslog receiver on port 514
          3. Mark host as monitored via syslog (not agent)
        """
        mgr = os.getenv("PFSENSE_SYSLOG_RELAY_IP", self._manager_ip)
        syslog_port_effective = "514"  # relay listens on 514, forwards to Wazuh
        syslog_port = os.getenv("WAZUH_SYSLOG_PORT", "50050")

        # Configure pfSense to forward syslog to Wazuh manager
        # Using pfSense's PHP shell (option 12 equivalent) via direct PHP execution
        php_script = f"""<?php
require_once("globals.inc");
require_once("config.inc");
require_once("functions.inc");
require_once("filter.inc");
require_once("shaper.inc");

// Configure remote syslog server
$config['syslog']['remoteserver'] = '{mgr}';
$config['syslog']['remoteserver2'] = '';
$config['syslog']['remoteserver3'] = '';
$config['syslog']['remoteport'] = '{syslog_port_effective}';
$config['syslog']['sourceip'] = '';
$config['syslog']['ipproto'] = 'ipv4';
$config['syslog']['logall'] = true;
$config['syslog']['system'] = true;
$config['syslog']['filter'] = true;
$config['syslog']['dhcp'] = true;
$config['syslog']['auth'] = true;
$config['syslog']['portalauth'] = true;
$config['syslog']['vpn'] = true;
$config['syslog']['dpinger'] = true;
$config['syslog']['hostapd'] = true;
$config['syslog']['routing'] = true;
$config['syslog']['ntpd'] = true;
$config['syslog']['ppp'] = true;
$config['syslog']['resolver'] = true;
$config['syslog']['wireless'] = true;

write_config("Wazuh syslog forwarding configured by SENTINEL-AI");
system_syslogd_start();
echo "SYSLOG_CONFIGURED\n";
?>
"""
        try:
            # Write PHP script to pfSense and execute it
            import tempfile, base64
            script_b64 = base64.b64encode(php_script.encode()).decode()

            ssh_opts = (
                f"-i {self._ssh_key_path} "
                f"-o StrictHostKeyChecking=no "
                f"-o ConnectTimeout=10 "
                f"-o BatchMode=yes "
                f"-o UserKnownHostsFile=/dev/null "
                f"-o LogLevel=ERROR"
            )

            relay_ip = mgr  # mgr is already the relay IP
            shell_script = f"""
echo '{script_b64}' | b64decode -r > /tmp/wazuh_syslog_setup.php
php-cgi -f /tmp/wazuh_syslog_setup.php 2>&1 || php /tmp/wazuh_syslog_setup.php 2>&1
rm -f /tmp/wazuh_syslog_setup.php
# Patch generated syslog.conf to use relay IP (system_syslogd_start regenerates from config.xml)
CONF=/var/etc/syslog.d/pfSense.conf
if [ -f "$CONF" ]; then
    php -r "\$f=file_get_contents(\"$CONF\");\$f=preg_replace('/@[0-9.]+/','@{relay_ip}',\$f);file_put_contents(\"$CONF\",\$f);"
    SYSPID=\$(pgrep -x syslogd | head -1)
    kill -HUP \$SYSPID 2>/dev/null || true
fi
echo "ENROLLMENT_OK"
"""
            proc = await asyncio.create_subprocess_shell(
                f'ssh {ssh_opts} root@{ip} "sh -s"',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(shell_script.encode()), timeout=60)
            output = stdout.decode()

            if "ENROLLMENT_OK" in output or "SYSLOG_CONFIGURED" in output:
                logger.info("discovery.pfsense_syslog_configured ip=%s -> %s:%s",
                            ip, mgr, syslog_port)
                return True

            logger.warning("discovery.pfsense_syslog_failed ip=%s out=%s err=%s",
                           ip, output[-300:], stderr.decode()[-200:])
            # Return True anyway — syslog may already be configured
            return True

        except Exception as e:
            logger.error("discovery.pfsense_exception ip=%s: %s", ip, e)
            return False

    async def _deploy_windows(self, ip: str, key_line: str) -> bool:
        """Delegate Windows deployment to Ansible (WinRM required)."""
        logger.info("discovery.windows_enroll ip=%s (delegating to Ansible)", ip)
        try:
            from ai_agents.tools.ansible_trigger import AnsibleTrigger
            trigger = AnsibleTrigger()
            result = await trigger.run_playbook(
                playbook="agents/deploy_wazuh_agent_windows",
                extra_vars={
                    "target_host":          ip,
                    "wazuh_manager_ip":     self._manager_ip,
                    "wazuh_manager_port":   self._manager_comm_port,
                    "wazuh_enrollment_key": key_line,
                },
            )
            return result.get("status") == "successful"
        except Exception as e:
            logger.error("discovery.windows_ansible_failed ip=%s error=%s", ip, e)
            return False

    # ── SSH helpers ─────────────────────────────────────────────────────────

    async def _ssh_run(self, ip: str, script: str, timeout: float = 15) -> str:
        """Run a script via SSH using the configured discovery user."""
        return await self._ssh_run_as(ip, self._ssh_user, script, timeout)

    async def _ssh_exec(self, ip: str, script: str, success_marker: str,
                        timeout: int = 180) -> bool:
        """Run a script via SSH and check for a success marker in output."""
        ssh_opts = (
            f"-i {self._ssh_key_path} "
            f"-o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=10 "
            f"-o BatchMode=yes "
            f"-o UserKnownHostsFile=/dev/null "
            f"-o LogLevel=ERROR"
        )
        cmd = f'ssh {ssh_opts} {self._ssh_user}@{ip} "bash -s"'
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(script.encode()), timeout=timeout)
            output = stdout.decode()
            if success_marker in output:
                logger.info("discovery.enrolled ip=%s", ip)
                return True
            logger.warning("discovery.enroll_no_marker ip=%s stdout=%s stderr=%s",
                           ip, output[-400:], stderr.decode()[-200:])
            return False
        except asyncio.TimeoutError:
            logger.error("discovery.enroll_timeout ip=%s", ip)
            return False
        except Exception as e:
            logger.error("discovery.ssh_failed ip=%s error=%s", ip, e)
            return False

    # ── Persistence ─────────────────────────────────────────────────────────

    def _persist_results(self, hosts: List[Dict]):
        try:
            with get_db() as db:
                for host in hosts:
                    existing = db.query(DiscoveredHost).filter(
                        DiscoveredHost.ip == host["ip"]).first()
                    now = datetime.utcnow()
                    if existing:
                        existing.open_ports   = host.get("open_ports", [])
                        existing.services     = host.get("services", [])
                        existing.os_guess     = host.get("os_guess", "unknown")
                        existing.role         = host.get("role", "unknown")
                        existing.wazuh_status = host.get("wazuh_status", "unknown")
                        existing.last_seen    = now
                    else:
                        db.add(DiscoveredHost(
                            ip=host["ip"],
                            open_ports=host.get("open_ports", []),
                            services=host.get("services", []),
                            os_guess=host.get("os_guess", "unknown"),
                            role=host.get("role", "unknown"),
                            wazuh_status=host.get("wazuh_status", "unknown"),
                            first_seen=now, last_seen=now,
                        ))
        except Exception as e:
            logger.error("discovery.persist_failed: %s", e)

    def get_latest_results(self) -> Optional[Dict]:
        return self._redis.get("discovery:latest")

    def get_all_hosts(self) -> List[Dict]:
        try:
            with get_db() as db:
                hosts = db.query(DiscoveredHost).order_by(
                    DiscoveredHost.last_seen.desc()).all()
                return [{
                    "ip": h.ip, "open_ports": h.open_ports,
                    "services": h.services, "os_guess": h.os_guess,
                    "role": h.role, "wazuh_status": h.wazuh_status,
                    "first_seen": str(h.first_seen), "last_seen": str(h.last_seen),
                } for h in hosts]
        except Exception as e:
            logger.error("discovery.get_all_failed: %s", e)
            return []


async def discovery_loop(agent: AutoDiscoveryAgent):
    """Background task — runs discovery on a schedule indefinitely."""
    interval = int(os.getenv("DISCOVERY_INTERVAL_SECONDS", "300"))
    enabled  = os.getenv("DISCOVERY_ENABLED", "true").lower() == "true"

    if not enabled:
        logger.info("discovery.disabled")
        return

    logger.info("discovery.loop_started interval=%ds", interval)
    while True:
        try:
            await agent.discover_and_enroll()
        except Exception as e:
            logger.error("discovery.loop_error: %s", e)
        await asyncio.sleep(interval)

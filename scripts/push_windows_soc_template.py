#!/usr/bin/env python3
"""
Push the Windows SOC template (ossec_windows.conf) to enrolled Windows agents.

v3 (FINAL): Uses scp to upload the file as raw bytes, then PS Copy-Item.
This avoids the Set-Content -Encoding UTF8 BOM bug that caused the agent
to silently fall back to the MSI default config in v1/v2.

Reverse on each agent (PowerShell as admin):
    Stop-Service WazuhSvc
    Copy-Item "C:\\Program Files (x86)\\ossec-agent\\ossec.conf.prebackup-soc" `
              "C:\\Program Files (x86)\\ossec-agent\\ossec.conf" -Force
    Start-Service WazuhSvc
"""
import base64
import re
import subprocess
import sys
from pathlib import Path

REPO = Path.home() / "sentinel-ai-commander"
TEMPLATE = REPO / "wazuh" / "config" / "agents" / "ossec_windows.conf"
SSH_KEY = REPO / "ansible" / "keys" / "id_rsa"

ENV = {}
for line in (REPO / ".env").read_text().splitlines():
    if "=" in line and not line.strip().startswith("#"):
        k, _, v = line.partition("=")
        ENV[k.strip()] = v.strip()
MANAGER_IP = ENV.get("WAZUH_MANAGER_EXTERNAL_IP") or ENV.get("WAZUH_MANAGER_IP") or "172.31.70.13"
MANAGER_PORT = ENV.get("PORT_WAZUH_AGENT_COMM_TCP") or "50041"

AGENTS = [
    {"name": "Win10-agent",         "ip": "192.168.49.136", "user": "Louay"},
    {"name": "Win11-agent-2",       "ip": "192.168.49.137", "user": "louaytorjmen"},
    {"name": "WinServer2019-agent", "ip": "192.168.49.138", "user": "Administrator"},
]

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; DIM = "\033[2m"; RST = "\033[0m"


def ps_encode(script):
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def ssh_ps(ip, user, ps_script, timeout=120):
    encoded = ps_encode(ps_script)
    cmd = [
        "ssh", "-i", str(SSH_KEY),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        f"{user}@{ip}",
        f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = r.stdout or ""
        err = r.stderr or ""
        if "<Objs " in out:
            out = "\n".join(l for l in out.split("\n")
                            if "<Objs " not in l
                            and not l.startswith("#< CLIXML")
                            and "schemas.microsoft.com" not in l).strip()
        if "<Objs " in err:
            err = "\n".join(l for l in err.split("\n")
                            if "<Objs " not in l
                            and not l.startswith("#< CLIXML")
                            and "schemas.microsoft.com" not in l).strip()
        return out, err, r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1


def render_template():
    template = TEMPLATE.read_text(encoding="utf-8")
    template = re.sub(r'<address>[^<]+</address>',
                      f'<address>{MANAGER_IP}</address>', template, count=1)
    template = re.sub(r'<port>\d+</port>',
                      f'<port>{MANAGER_PORT}</port>', template, count=1)
    return template


def scp_upload(ip, user, local_path, remote_path):
    cmd = [
        "scp", "-i", str(SSH_KEY),
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        str(local_path),
        f"{user}@{ip}:{remote_path}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return r.returncode == 0, r.stderr


def push(agent, rendered_local_path):
    print(f"\n{C}── {agent['name']} ({agent['ip']}, user={agent['user']}) ──{RST}")

    # Reachability test
    out, err, rc = ssh_ps(agent['ip'], agent['user'], "Write-Output OK", timeout=15)
    if rc != 0 or "OK" not in out:
        print(f"  {R}[!] SSH failed: rc={rc} err={err[:120]}{RST}")
        return False
    print(f"  {DIM}SSH OK{RST}")

    # 1. scp upload (avoids Set-Content BOM bug entirely - file goes as raw bytes)
    user = agent['user']
    remote_tmp = f"C:/Users/{user}/AppData/Local/Temp/ossec_windows_v3.conf"
    ok, scp_err = scp_upload(agent['ip'], user, rendered_local_path, remote_tmp)
    if not ok:
        print(f"  {R}[!] scp failed: {scp_err[:200]}{RST}")
        return False
    print(f"  {DIM}Uploaded template via scp{RST}")

    # 2. PowerShell: stop service, swap config, restart
    swap_ps = (
        '$ErrorActionPreference = "Stop"\n'
        '$conf = "C:\\Program Files (x86)\\ossec-agent\\ossec.conf"\n'
        f'$src  = "{remote_tmp.replace("/", chr(92))}"\n'
        'Stop-Service WazuhSvc -ErrorAction SilentlyContinue\n'
        'Start-Sleep -Seconds 2\n'
        '$backup = "$conf.prebackup-soc"\n'
        'if (-not (Test-Path $backup)) { Copy-Item $conf $backup -Force }\n'
        'Copy-Item $src $conf -Force\n'
        'Write-Output ("wrote_bytes=" + (Get-Item $conf).Length)\n'
        '# Validation: confirm critical content survived\n'
        '$content = Get-Content $conf -Raw\n'
        'if ($content -match "C:\\\\Users\\\\Public") { Write-Output "validate=ok_users_public" } else { Write-Output "validate=FAIL_users_public" }\n'
        'if ($content -match \'realtime="yes"\') { Write-Output "validate=ok_realtime" } else { Write-Output "validate=FAIL_realtime" }\n'
        'Start-Service WazuhSvc\n'
        '$tries = 0\n'
        'do {\n'
        '  Start-Sleep -Seconds 2\n'
        '  $status = (Get-Service WazuhSvc).Status\n'
        '  $tries++\n'
        '} while ($status -ne "Running" -and $tries -lt 30)\n'
        'Start-Sleep -Seconds 2\n'
        '$final = (Get-Service WazuhSvc).Status\n'
        'Write-Output ("service_status=" + $final)\n'
        'Start-Sleep -Seconds 8\n'
        '$log = Get-Content "C:\\Program Files (x86)\\ossec-agent\\ossec.log" -Tail 50\n'
        '$conn = $log | Select-String "Connected to the server" | Select-Object -Last 1\n'
        '$realtime = $log | Select-String "(6012)" | Select-Object -Last 1\n'
        'if ($conn) { Write-Output ("conn=ok") } else { Write-Output "conn=PENDING" }\n'
        'if ($realtime) { Write-Output ("realtime=ok") } else { Write-Output "realtime=NOT_STARTED" }\n'
        '# Cleanup temp\n'
        'Remove-Item $src -Force -ErrorAction SilentlyContinue\n'
    )
    out, err, rc = ssh_ps(agent['ip'], user, swap_ps, timeout=120)
    for line in (out or "").split("\n"):
        if line.strip():
            print(f"  {line}")

    if "service_status=Running" not in out:
        print(f"  {R}[!] WazuhSvc not running{RST}")
        return False
    if "validate=ok_users_public" not in out or "validate=ok_realtime" not in out:
        print(f"  {R}[!] Template content validation failed — old config may still be active{RST}")
        return False
    if "realtime=ok" in out:
        print(f"  {G}[+] OK — running, new SOC config active, realtime FIM started{RST}")
    else:
        print(f"  {Y}[~] Running with new config but realtime FIM not yet started (may take 30-60s){RST}")
    return True


def main():
    if not TEMPLATE.is_file():
        print(f"{R}ERROR: template not found at {TEMPLATE}{RST}")
        return 1

    print(f"{C}════════════════════════════════════════════════════════════{RST}")
    print(f"  Pushing SOC template to enrolled Windows agents (v3 — uses scp)")
    print(f"  Template: {TEMPLATE}")
    print(f"  Manager:  {MANAGER_IP}:{MANAGER_PORT}")
    print(f"{C}════════════════════════════════════════════════════════════{RST}")

    # Render template to a tmp file (with manager IP/port substituted)
    template_text = render_template()
    rendered = Path("/tmp/ossec_windows_rendered.conf")
    rendered.write_text(template_text, encoding="utf-8")
    print(f"\n  Rendered: {len(template_text)} bytes → {rendered}")
    if f"<address>{MANAGER_IP}</address>" not in template_text:
        print(f"  {R}WARNING: render failed — manager IP not found{RST}"); return 1
    if f"<port>{MANAGER_PORT}</port>" not in template_text:
        print(f"  {R}WARNING: render failed — manager port not found{RST}"); return 1

    results = {}
    for agent in AGENTS:
        results[agent['name']] = push(agent, rendered)

    print(f"\n{C}═════════════ SUMMARY ═════════════{RST}")
    for name, ok in results.items():
        marker = f"{G}✓{RST}" if ok else f"{R}✗{RST}"
        print(f"  {marker}  {name}")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

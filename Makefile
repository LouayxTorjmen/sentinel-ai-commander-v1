.PHONY: preflight setup certs \
       phase1 phase2 phase3 phase4 phase5 \
       wazuh-up wazuh-down wazuh-check wazuh-logs \
       infra-up infra-down suricata-up suricata-down ai-up ai-down \
       stack-up stack-down stack-logs \
       up down restart logs ps test clean help \
       deploy-agents train-ml ollama-pull

# ─── Setup ────────────────────────────────────────────────────────────────────
preflight:
	@bash scripts/preflight.sh

setup:
	@[ -f .env ] || cp .env.example .env
	@echo "Edit .env with your passwords and API keys, then run: make phase1"

certs:
	@bash scripts/gen_certs.sh

# ─── Phased Deployment ───────────────────────────────────────────────────────
phase1: ## Deploy Wazuh stack
	@bash scripts/phase1_wazuh.sh

phase2: ## Deploy infrastructure (PostgreSQL, Redis, Nginx)
	@bash scripts/phase2_database.sh

phase3: ## Deploy Suricata IDS
	@bash scripts/phase3_suricata.sh

phase4: ## Deploy AI agents + Ansible Runner + Ollama
	@bash scripts/phase4_agents.sh

phase5: ## Run full test suite
	@bash scripts/phase5_test.sh

# ─── Independent Stack Operations (Point 1) ──────────────────────────────────
wazuh-up:
	cd wazuh && docker compose --env-file ../.env up -d

wazuh-down:
	cd wazuh && docker compose down

wazuh-check:
	@bash scripts/check_wazuh.sh

wazuh-logs:
	cd wazuh && docker compose logs -f

infra-up:
	docker compose -f docker-compose.infra.yml --env-file .env up -d

infra-down:
	docker compose -f docker-compose.infra.yml down

suricata-up:
	docker compose -f docker-compose.suricata.yml --env-file .env up -d

suricata-down:
	docker compose -f docker-compose.suricata.yml down

ai-up:
	docker compose -f docker-compose.ai.yml --env-file .env up -d

ai-down:
	docker compose -f docker-compose.ai.yml down

# ─── Unified (backward compat) ───────────────────────────────────────────────
stack-up:
	docker compose --env-file .env up -d

stack-down:
	docker compose down

stack-logs:
	docker compose logs -f

up: wazuh-up stack-up
down: stack-down wazuh-down
restart: down up
logs:
	docker compose logs -f

ps:
	@echo "=== Wazuh Stack ==="
	@cd wazuh && docker compose ps 2>/dev/null || true
	@echo ""
	@echo "=== Main Stack ==="
	@docker compose ps 2>/dev/null || true

test:
	@bash scripts/phase5_test.sh

# ─── Wazuh Agent Deployment (Point 3) ────────────────────────────────────────
deploy-agents: ## Deploy Wazuh agents to victim hosts + pfSense
	docker exec sentinel-ansible-runner ansible-playbook /ansible/playbooks/agents/deploy_wazuh_agent_linux.yml
	docker exec sentinel-ansible-runner ansible-playbook /ansible/playbooks/agents/deploy_pfsense_agent.yml

# ─── ML Training (Point 4) ───────────────────────────────────────────────────
train-ml: ## Train ML models from historical incidents
	curl -s -X POST http://127.0.0.1:50010/ml/train | python3 -m json.tool

# ─── Ollama Model Pull (Point 5) ─────────────────────────────────────────────
ollama-pull: ## Pull Ollama fallback model
	docker exec sentinel-ollama ollama pull llama3.2:3b

clean:
	docker compose down -v --remove-orphans 2>/dev/null || true
	cd wazuh && docker compose down -v --remove-orphans 2>/dev/null || true
	docker image prune -f

help:
	@echo "SENTINEL-AI COMMANDER v2"
	@echo ""
	@echo "Phased Deployment:"
	@echo "  make setup        - Create .env from template"
	@echo "  make phase1       - Deploy Wazuh (indexer, manager, dashboard)"
	@echo "  make phase2       - Deploy PostgreSQL, Redis, Nginx"
	@echo "  make phase3       - Deploy Suricata IDS"
	@echo "  make phase4       - Deploy AI agents + Ansible Runner + Ollama"
	@echo "  make phase5       - Run full test suite"
	@echo ""
	@echo "Independent Stacks (Point 1):"
	@echo "  make infra-up     - Start infrastructure only"
	@echo "  make suricata-up  - Start Suricata only"
	@echo "  make ai-up        - Start AI platform only"
	@echo ""
	@echo "New Features:"
	@echo "  make deploy-agents - Deploy 3 Wazuh agents (Point 3)"
	@echo "  make train-ml      - Train ML models (Point 4)"
	@echo "  make ollama-pull   - Pull Ollama fallback model (Point 5)"
	@echo ""
	@echo "Operations:"
	@echo "  make up / down / restart / ps / logs / test / clean"

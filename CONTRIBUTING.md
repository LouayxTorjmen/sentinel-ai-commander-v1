# Contributing to SENTINEL-AI Commander

Thanks for considering a contribution! Here's how to get set up and what to keep in mind.

## Development setup

1. Fork the repo and clone your fork
2. Run `./setup.sh` on a fresh VM (do NOT develop on prod)
3. Make changes, test them, and open a PR

## What makes a good PR

- **Scoped** — one change per PR, not a bundle of 5 unrelated things
- **Tested** — if you add a new playbook, show it running successfully in the PR description
- **Documented** — if you add an env var, update `.env.example` and README
- **Secrets-free** — never commit `.env`, `keys/`, or `certs/` (hooks should catch this, but double-check)

## Adding a new playbook

1. Add the role to `ansible/roles/<your_role>/` with `tasks/main.yml` and `defaults/main.yml`
2. Add the playbook to `ansible/playbooks/<your>_response.yml`
3. Add it to the allowlist in `docker/ansible-runner/runner_api.py`
4. Add a routing entry in `ai_agents/agents/ansible_dispatch/ansible_dispatch_agent.py`:
   - Either in `STATIC_RULE_MAP` (if mapped to a specific Wazuh rule ID)
   - Or in `GROUP_HEURISTICS` (if matched by rule groups)
5. Update the README playbook table
6. Test with `dry_run=true` first, then for real

## Adding an agent type

Currently only Linux is supported. To add macOS or Windows:

1. Add OS detection to `enroll.py`'s `detect_os()` function
2. Add the Wazuh agent package URL pattern to `get_wazuh_pkg_url()`
3. Add install commands to `deploy_wazuh()` and `deploy_suricata()`
4. Test on a fresh VM of that OS

## Reporting bugs

Open an issue with:

- OS and version
- Docker version (`docker --version`)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (`docker logs sentinel-ai-agents`, etc.)
- Whether you're on a fresh install or upgrade

## Security issues

**Do NOT open a public issue** for security vulnerabilities. Email the maintainer directly (see repo owner profile).

## Code style

- Python: PEP 8 (use `ruff` or `black`)
- Ansible: 2-space indent, explicit task names
- Shell: shellcheck-clean
- YAML: 2-space indent, no trailing whitespace

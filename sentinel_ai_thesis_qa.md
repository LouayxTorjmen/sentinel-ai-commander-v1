
## Session Summary — June 3, 2026

### All Playbooks Working
| Rule | Description | Playbook | Status |
|------|-------------|----------|--------|
| 100130 | Suricata ET SCAN | block_ip | ✅ |
| 100114/100115 | Falco sensitive read | incident_response | ✅ |
| 100150 | Webshell activity | incident_response | ✅ |
| 100601/100602 | Weak TLS nginx | harden_nginx_tls | ✅ |
| 100611/100612 | MySQL credential theft | mysql_credential_response | ✅ |
| 31103/31152 | SQL/PHP injection | incident_response | ✅ |
| 100620 | NTLM lateral to DC | win_lateral_movement_response | ✅ |
| 100720 | SSH lateral movement | block_ip | ✅ |
| 100750/100751 | DoH exfiltration | block_dns_exfil | ✅ |
| 100534/100536 | AD CS ESC1 abuse | block_adcs_abuse | ✅ |
| 100710/100711 | Kerberoast | win_incident_response | ✅ |
| 100112 | SSH key search | incident_response | ✅ |
| 550 | FIM file change | fim_restore_response | ✅ |

### Key Engineering Fixes
- Removed LLM fallback — static-only dispatch, instant processing
- Bypass LLM orchestrator pipeline for non-static-map rules
- Dynamic inventory always includes all agents regardless of Wazuh status
- Wazuh agents auto-restart on Windows hosts
- DoH detection: iptables LOG → rsyslog → formatter → SENTINEL_AI_DOH
- nginx TLS: SENTINEL_TLS log format → decoder → rule 100601
- mini_rearm.sh preserves webshell between acts

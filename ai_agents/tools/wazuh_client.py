# =============================================================================
#  wazuh_client.py — Wazuh Client (OpenSearch + Manager API)
#
#  Alerts come from OpenSearch (wazuh-alerts-* index)
#  Agent management comes from Manager REST API (JWT auth)
# =============================================================================
from __future__ import annotations

import os
import time
import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class WazuhAPIError(Exception):
    pass


class WazuhClient:
    _TOKEN_TTL: int = 840

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        indexer_url: Optional[str] = None,
        indexer_user: Optional[str] = None,
        indexer_password: Optional[str] = None,
    ) -> None:
        # Manager API config
        self._base_url = (
            base_url or os.getenv("WAZUH_API_URL", "https://sentinel-wazuh-manager:55000")
        ).rstrip("/")
        self._username = username or os.getenv("WAZUH_API_USER", "wazuh-wui")
        self._password = password or os.getenv("WAZUH_API_PASSWORD", "")

        # OpenSearch indexer config (for alert queries)
        self._indexer_url = (
            indexer_url
            or os.getenv("WAZUH_INDEXER_URL", f"https://{os.getenv('WAZUH_INDEXER_HOST', 'sentinel-wazuh-indexer')}:{os.getenv('WAZUH_INDEXER_PORT', '9200')}")
        ).rstrip("/")
        self._indexer_user = indexer_user or os.getenv("WAZUH_INDEXER_USER", "admin")
        self._indexer_password = indexer_password or os.getenv("WAZUH_INDEXER_PASSWORD", "")

        # SSL
        if verify_ssl is None:
            verify_ssl_env = os.getenv("WAZUH_SSL_VERIFY", "false").lower()
            verify_ssl = verify_ssl_env not in ("false", "0", "no")
        self._verify_ssl = verify_ssl

        self._token: Optional[str] = None
        self._token_fetched_at: float = 0.0

        # Session with retry
        self._session = requests.Session()
        retry = Retry(total=3, backoff_factor=1.0, status_forcelist=(502, 503, 504))
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

        if not self._verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Manager JWT Auth ──────────────────────────────────────────────────────

    def _refresh_token(self) -> None:
        url = f"{self._base_url}/security/user/authenticate"
        try:
            resp = self._session.post(
                url, auth=(self._username, self._password),
                verify=self._verify_ssl, timeout=15,
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            self._token_fetched_at = time.monotonic()
        except requests.RequestException as exc:
            raise WazuhAPIError(f"Wazuh authentication failed: {exc}") from exc

    @property
    def _auth_headers(self) -> Dict[str, str]:
        if self._token is None or (time.monotonic() - self._token_fetched_at) >= self._TOKEN_TTL:
            self._refresh_token()
        return {"Authorization": f"Bearer {self._token}"}

    def _manager_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        kwargs.setdefault("verify", self._verify_ssl)
        kwargs.setdefault("timeout", 30)
        for attempt in range(2):
            try:
                resp = self._session.request(method, url, headers=self._auth_headers, **kwargs)
                if resp.status_code == 401 and attempt == 0:
                    self._token = None
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                if attempt == 0:
                    self._token = None
                    continue
                raise WazuhAPIError(f"Wazuh API [{method} {path}]: {exc}") from exc
        raise WazuhAPIError(f"Exhausted retries for {method} {path}")

    # ── OpenSearch Queries (for alerts) ───────────────────────────────────────

    def _indexer_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self._indexer_url}{path}"
        kwargs.setdefault("verify", self._verify_ssl)
        kwargs.setdefault("timeout", 30)
        try:
            resp = self._session.request(
                method, url,
                auth=(self._indexer_user, self._indexer_password),
                **kwargs,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise WazuhAPIError(f"OpenSearch [{method} {path}]: {exc}") from exc

    # ── Public API: Alerts (from OpenSearch) ──────────────────────────────────

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        level_gte: int = 0,
        sort: str = "-timestamp",
        query: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        body: Dict[str, Any] = {
            "size": min(limit, 500),
            "from": offset,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": []}},
        }

        if level_gte > 0:
            body["query"]["bool"]["must"].append(
                {"range": {"rule.level": {"gte": level_gte}}}
            )

        if query:
            body["query"]["bool"]["must"].append(
                {"query_string": {"query": query}}
            )

        if not body["query"]["bool"]["must"]:
            body["query"] = {"match_all": {}}

        data = self._indexer_request(
            "POST", "/wazuh-alerts-*/_search",
            json=body,
            headers={"Content-Type": "application/json"},
        )

        hits = data.get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]

    def get_alerts_by_mitre(self, technique_id: str, limit: int = 50) -> List[Dict]:
        return self.get_alerts(limit=limit, query=f"rule.mitre.id:{technique_id}")

    # ── Public API: Agents (from Manager) ─────────────────────────────────────

    def get_agents(self, status: str = "active") -> List[Dict[str, Any]]:
        data = self._manager_request("GET", "/agents", params={"status": status, "limit": 500})
        return data.get("data", {}).get("affected_items", [])

    def get_agent_vulnerabilities(self, agent_id: str) -> List[Dict[str, Any]]:
        data = self._manager_request("GET", f"/vulnerability/{agent_id}", params={"limit": 500})
        return data.get("data", {}).get("affected_items", [])

    def get_statistics(self) -> Dict[str, Any]:
        mgr_stats = self._manager_request("GET", "/manager/stats")
        return {"manager_stats": mgr_stats.get("data", {})}

    def run_active_response(
        self, command: str, agent_ids: List[str],
        arguments: Optional[List[str]] = None, timeout: int = 60,
    ) -> Dict[str, Any]:
        payload = {"command": command, "arguments": arguments or [], "timeout": timeout}
        data = self._manager_request(
            "PUT", "/active-response",
            json=payload, params={"agents_list": ",".join(agent_ids)},
        )
        return data

    def health_check(self) -> bool:
        try:
            # Check both Manager and Indexer
            mgr = self._manager_request("GET", "/")
            idx = self._indexer_request("GET", "/")
            return mgr.get("title") is not None and idx.get("cluster_name") is not None
        except WazuhAPIError:
            return False

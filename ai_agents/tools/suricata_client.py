# =============================================================================
#  suricata_client.py — Suricata Eve JSON Integration Client
#  Location: src/integrations/suricata_client.py
#
#  PURPOSE:
#    Reads and parses Suricata IDS/IPS alert events from eve.json.
#    Provides two ingestion modes depending on deployment topology:
#
#    Mode A — Redis pub/sub (default, recommended for isolated Wazuh stack):
#      A lightweight log-shipper sidecar reads Suricata's eve.json and publishes
#      alert events to the Redis channel "suricata:alerts".
#      The WazuhSuricataAgent subscribes and processes events in real-time.
#
#    Mode B — Shared Docker volume (Option B in ossec.conf):
#      The AI agent reads eve.json directly from a shared Docker volume.
#      Useful for simple single-host lab setups.
#
#  USED BY:
#    - src/ai_agents/wazuh_suricata_agent.py
#    - api/main.py  /alerts/suricata endpoint
#
#  ENVIRONMENT VARIABLES:
#    SURICATA_EVE_PATH   → /var/log/suricata/eve.json
#    REDIS_HOST          → redis (Docker service name)
#    REDIS_PORT          → 6379
#    SURICATA_REDIS_CH   → suricata:alerts
# =============================================================================

from __future__ import annotations

import json
import logging
import os
import time
from typing import Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


class SuricataEvent:
    """
    Parsed Suricata Eve JSON event with convenience accessors.

    Attributes mirror Suricata's eve.json schema:
      https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
    """

    __slots__ = (
        "timestamp",
        "event_type",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
        "alert",
        "flow_id",
        "raw",
    )

    def __init__(self, raw: Dict) -> None:
        self.raw = raw
        self.timestamp: str = raw.get("timestamp", "")
        self.event_type: str = raw.get("event_type", "")
        self.src_ip: str = raw.get("src_ip", "")
        self.src_port: int = raw.get("src_port", 0)
        self.dest_ip: str = raw.get("dest_ip", "")
        self.dest_port: int = raw.get("dest_port", 0)
        self.proto: str = raw.get("proto", "")
        self.alert: Dict = raw.get("alert", {})
        self.flow_id: Optional[int] = raw.get("flow_id")

    # ── Alert-specific accessors ──────────────────────────────────────────────

    @property
    def signature(self) -> str:
        """Suricata rule signature text, e.g. 'ET SCAN Nmap Scripting Engine'."""
        return self.alert.get("signature", "")

    @property
    def signature_id(self) -> int:
        """Suricata rule SID (signature ID)."""
        return self.alert.get("signature_id", 0)

    @property
    def category(self) -> str:
        """Suricata rule category, e.g. 'Attempted Information Leak'."""
        return self.alert.get("category", "")

    @property
    def severity(self) -> int:
        """
        Suricata severity level: 1 (critical) to 4 (informational).
        Note: Suricata severity is INVERTED compared to Wazuh rule levels.
        """
        return self.alert.get("severity", 3)

    @property
    def action(self) -> str:
        """'allowed' (IDS mode) or 'blocked' (IPS mode with drop rules)."""
        return self.alert.get("action", "allowed")

    @property
    def mitre_attack(self) -> Dict:
        """
        MITRE ATT&CK metadata if the rule includes it.
        Returns dict with 'technique_id', 'technique_name', 'tactic' if present.
        """
        return self.alert.get("metadata", {}).get("mitre_attack", {})

    @property
    def is_critical(self) -> bool:
        """True if severity == 1 (Suricata's highest severity)."""
        return self.severity == 1

    def to_dict(self) -> Dict:
        """Return a flattened dict for easy ingestion into DSPy signatures."""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "proto": self.proto,
            "signature": self.signature,
            "signature_id": self.signature_id,
            "category": self.category,
            "severity": self.severity,
            "action": self.action,
            "mitre_attack": self.mitre_attack,
            "flow_id": self.flow_id,
        }

    def __repr__(self) -> str:
        return (
            f"<SuricataEvent {self.event_type} "
            f"src={self.src_ip}:{self.src_port} "
            f"sig='{self.signature}' sev={self.severity}>"
        )


class SuricataClient:
    """
    Client for ingesting Suricata IDS/IPS alert events.

    Supports two modes:

    1. **File tail** (Mode B — shared Docker volume):
       ``client = SuricataClient(mode='file')``

    2. **Redis pub/sub** (Mode A — recommended for isolated Wazuh stack):
       ``client = SuricataClient(mode='redis')``
    """

    def __init__(
        self,
        mode: str = "redis",
        eve_path: Optional[str] = None,
        redis_host: Optional[str] = None,
        redis_port: Optional[int] = None,
        redis_channel: Optional[str] = None,
    ) -> None:
        """
        Args:
            mode:          'redis' (default) or 'file'.
            eve_path:      Path to eve.json (only for mode='file').
                           Defaults to SURICATA_EVE_PATH env var or
                           /var/log/suricata/eve.json.
            redis_host:    Redis hostname. Defaults to REDIS_HOST env or 'redis'.
            redis_port:    Redis port. Defaults to REDIS_PORT env or 6379.
            redis_channel: Redis pub/sub channel. Defaults to
                           SURICATA_REDIS_CH env or 'suricata:alerts'.
        """
        self.mode = mode

        # File mode settings
        self._eve_path = eve_path or os.getenv(
            "SURICATA_EVE_PATH", "/var/log/suricata/eve.json"
        )

        # Redis mode settings
        self._redis_host = redis_host or os.getenv("REDIS_HOST", "redis")
        self._redis_port = int(redis_port or os.getenv("REDIS_PORT", "6379"))
        self._redis_channel = redis_channel or os.getenv(
            "SURICATA_REDIS_CH", "suricata:alerts"
        )

        self._redis_client = None
        self._pubsub = None

        if self.mode == "redis":
            self._connect_redis()

    # ── Redis mode ────────────────────────────────────────────────────────────

    def _connect_redis(self) -> None:
        """Establish Redis connection (graceful degradation if unavailable)."""
        try:
            import redis as redis_lib

            client = redis_lib.Redis(
                host=self._redis_host,
                port=self._redis_port,
                db=0,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
            )
            client.ping()
            self._redis_client = client
            self._pubsub = client.pubsub()
            self._pubsub.subscribe(self._redis_channel)
            logger.info(
                "SuricataClient: subscribed to Redis channel '%s'",
                self._redis_channel,
            )
        except Exception as exc:
            logger.warning(
                "SuricataClient: Redis unavailable (%s). "
                "Falling back to file mode if needed.",
                exc,
            )
            self._redis_client = None

    def poll_redis(
        self, timeout: float = 0.1, max_events: int = 100
    ) -> List[SuricataEvent]:
        """
        Non-blocking poll for Suricata alert events from Redis pub/sub.

        Args:
            timeout:    get_message timeout in seconds.
            max_events: Maximum events to return per call.

        Returns:
            List of SuricataEvent objects (may be empty).
        """
        if not self._redis_client or not self._pubsub:
            logger.warning("SuricataClient.poll_redis: Redis not available.")
            return []

        events: List[SuricataEvent] = []
        for _ in range(max_events):
            message = self._pubsub.get_message(timeout=timeout)
            if message is None:
                break
            if message.get("type") != "message":
                continue
            try:
                raw = json.loads(message["data"])
                evt = SuricataEvent(raw)
                if evt.event_type == "alert":
                    events.append(evt)
            except (json.JSONDecodeError, KeyError) as exc:
                logger.debug("SuricataClient: skipping malformed message: %s", exc)

        return events

    def get_recent_alerts_from_redis(
        self, limit: int = 50, severity_lte: int = 3
    ) -> List[SuricataEvent]:
        """
        Fetch recent alerts buffered in Redis (list key: suricata:recent_alerts).

        The Suricata log-shipper sidecar maintains this rolling list in addition
        to pub/sub, so the WazuhSuricataAgent can retrieve the last N alerts
        on startup without waiting for new events.

        Args:
            limit:       Max alerts to return.
            severity_lte: Only return alerts with severity <= this value.
                          (1=critical only, 3=critical+major+minor)

        Returns:
            List of SuricataEvent objects.
        """
        if not self._redis_client:
            return []

        try:
            raw_list = self._redis_client.lrange(
                "suricata:recent_alerts", 0, limit - 1
            )
            events = []
            for raw_str in raw_list:
                try:
                    raw = json.loads(raw_str)
                    evt = SuricataEvent(raw)
                    if evt.event_type == "alert" and evt.severity <= severity_lte:
                        events.append(evt)
                except (json.JSONDecodeError, KeyError):
                    continue
            return events
        except Exception as exc:
            logger.error("SuricataClient.get_recent_alerts_from_redis: %s", exc)
            return []

    # ── File mode (Mode B) ────────────────────────────────────────────────────

    def tail_file(
        self,
        poll_interval: float = 1.0,
        only_alerts: bool = True,
    ) -> Generator[SuricataEvent, None, None]:
        """
        Tail eve.json and yield SuricataEvent objects as they are written.

        This is a blocking generator — run it in a background thread.

        Args:
            poll_interval: Seconds between file reads when no new lines appear.
            only_alerts:   If True, yield only event_type=='alert' events.

        Yields:
            SuricataEvent for each parsed line.

        Example::

            for event in client.tail_file():
                print(event)
        """
        if not os.path.exists(self._eve_path):
            logger.error(
                "SuricataClient.tail_file: eve.json not found at %s. "
                "Is Suricata running and the volume mounted?",
                self._eve_path,
            )
            return

        logger.info("SuricataClient: tailing %s", self._eve_path)

        with open(self._eve_path, "r") as fh:
            # Seek to end — only process new events from this point on
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(poll_interval)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    evt = SuricataEvent(raw)
                    if only_alerts and evt.event_type != "alert":
                        continue
                    yield evt
                except json.JSONDecodeError as exc:
                    logger.debug("SuricataClient: JSON parse error: %s", exc)

    def read_recent_from_file(
        self, last_n_lines: int = 500, only_alerts: bool = True
    ) -> List[SuricataEvent]:
        """
        Read the last N lines of eve.json and return parsed events.

        Used for on-demand historical lookback (e.g., API endpoint /alerts/suricata).

        Args:
            last_n_lines: Number of lines to read from end of file.
            only_alerts:  If True, return only alert events.

        Returns:
            List of SuricataEvent objects (most recent first).
        """
        if not os.path.exists(self._eve_path):
            logger.warning(
                "SuricataClient.read_recent_from_file: %s not found.", self._eve_path
            )
            return []

        # Efficient tail implementation using seek
        try:
            with open(self._eve_path, "rb") as fh:
                fh.seek(0, 2)
                file_size = fh.tell()

                chunk_size = min(file_size, 1024 * 1024)  # 1 MB max chunk
                fh.seek(max(0, file_size - chunk_size))
                lines = fh.read().decode("utf-8", errors="replace").splitlines()

            lines = lines[-last_n_lines:]

            events: List[SuricataEvent] = []
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    evt = SuricataEvent(raw)
                    if only_alerts and evt.event_type != "alert":
                        continue
                    events.append(evt)
                except json.JSONDecodeError:
                    continue

            return events
        except OSError as exc:
            logger.error("SuricataClient.read_recent_from_file: %s", exc)
            return []

    def health_check(self) -> Dict[str, bool]:
        """Return dict with 'redis_ok' and 'file_ok' health flags."""
        redis_ok = self._redis_client is not None
        if redis_ok:
            try:
                self._redis_client.ping()
            except Exception:
                redis_ok = False

        file_ok = os.path.exists(self._eve_path)

        return {"redis_ok": redis_ok, "file_ok": file_ok}

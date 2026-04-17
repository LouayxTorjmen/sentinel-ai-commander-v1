import json
import redis
import structlog
from typing import Any, Optional
from ai_agents.config import get_settings

logger = structlog.get_logger()

class RedisManager:
    def __init__(self):
        s = get_settings()
        self._client = redis.Redis(
            host=s.redis_host,
            port=s.redis_port,
            password=s.redis_password,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        self._ttl = s.redis_ttl_seconds

    def ping(self) -> bool:
        try:
            return self._client.ping()
        except Exception:
            return False

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        try:
            serialized = json.dumps(value, default=str)
            self._client.setex(key, ttl or self._ttl, serialized)
            return True
        except Exception as e:
            logger.error("redis.set.failed", key=key, error=str(e))
            return False

    def get(self, key: str) -> Optional[Any]:
        try:
            raw = self._client.get(key)
            return json.loads(raw) if raw else None
        except Exception as e:
            logger.error("redis.get.failed", key=key, error=str(e))
            return None

    def delete(self, key: str) -> bool:
        try:
            self._client.delete(key)
            return True
        except Exception as e:
            logger.error("redis.delete.failed", key=key, error=str(e))
            return False

    def publish(self, channel: str, message: Any) -> bool:
        try:
            self._client.publish(channel, json.dumps(message, default=str))
            return True
        except Exception as e:
            logger.error("redis.publish.failed", channel=channel, error=str(e))
            return False

    def subscribe(self, channel: str):
        pubsub = self._client.pubsub()
        pubsub.subscribe(channel)
        return pubsub

    def lpush(self, key: str, value: Any) -> bool:
        try:
            self._client.lpush(key, json.dumps(value, default=str))
            self._client.expire(key, self._ttl)
            return True
        except Exception as e:
            logger.error("redis.lpush.failed", key=key, error=str(e))
            return False

    def lrange(self, key: str, start: int = 0, end: int = -1) -> list:
        try:
            items = self._client.lrange(key, start, end)
            return [json.loads(i) for i in items]
        except Exception as e:
            logger.error("redis.lrange.failed", key=key, error=str(e))
            return []

_redis_manager: Optional[RedisManager] = None

def get_redis() -> RedisManager:
    global _redis_manager
    if _redis_manager is None:
        _redis_manager = RedisManager()
    return _redis_manager

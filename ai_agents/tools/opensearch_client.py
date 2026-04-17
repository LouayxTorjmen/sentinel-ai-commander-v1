from opensearchpy import AsyncOpenSearch
import structlog
from ai_agents.config import get_settings

logger = structlog.get_logger()

def get_opensearch_client() -> AsyncOpenSearch:
    s = get_settings()
    return AsyncOpenSearch(
        hosts=[{"host": s.wazuh_indexer_host, "port": s.wazuh_indexer_port}],
        http_auth=(s.wazuh_indexer_user, s.wazuh_indexer_password),
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
        timeout=30,
    )

async def search_alerts(query: dict, index: str = "wazuh-alerts-*", size: int = 100) -> list:
    client = get_opensearch_client()
    try:
        resp = await client.search(index=index, body=query, size=size)
        return resp["hits"]["hits"]
    except Exception as e:
        logger.error("opensearch.search.failed", error=str(e))
        return []
    finally:
        await client.close()

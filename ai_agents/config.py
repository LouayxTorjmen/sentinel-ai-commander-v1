from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache

class Settings(BaseSettings):
    log_level: str = Field("INFO", env="LOG_LEVEL")

    # Groq LLM (primary)
    groq_api_key: str = Field("", env="GROQ_API_KEY")
    llm_model: str = Field("llama-3.3-70b-versatile", env="LLM_MODEL")
    llm_temperature: float = Field(0, env="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(4096, env="LLM_MAX_TOKENS")

    # Ollama (fallback — Point 5)
    ollama_base_url: str = Field("http://sentinel-ollama:11434", env="OLLAMA_BASE_URL")
    ollama_model: str = Field("llama3.2:3b", env="OLLAMA_MODEL")
    llm_fallback_enabled: bool = Field(True, env="LLM_FALLBACK_ENABLED")

    # Wazuh
    wazuh_api_url: str = Field("https://sentinel-wazuh-manager:55000", env="WAZUH_API_URL")
    wazuh_ssl_verify: bool = Field(False, env="WAZUH_SSL_VERIFY")
    wazuh_manager_host: str = Field("sentinel-wazuh-manager", env="WAZUH_MANAGER_HOST")
    wazuh_api_user: str = Field("wazuh-wui", env="WAZUH_API_USER")
    wazuh_api_password: str = Field("", env="WAZUH_API_PASSWORD")
    wazuh_indexer_host: str = Field("sentinel-wazuh-indexer", env="WAZUH_INDEXER_HOST")
    wazuh_indexer_port: int = Field(9200, env="WAZUH_INDEXER_PORT")
    wazuh_indexer_user: str = Field("admin", env="WAZUH_INDEXER_USER")
    wazuh_indexer_password: str = Field("", env="WAZUH_INDEXER_PASSWORD")

    # Redis
    redis_host: str = Field("sentinel-redis", env="REDIS_HOST")
    redis_port: int = Field(6379, env="REDIS_PORT")
    redis_password: str = Field("", env="REDIS_PASSWORD")
    redis_ttl_seconds: int = Field(3600, env="REDIS_TTL_SECONDS")

    # PostgreSQL
    postgres_host: str = Field("sentinel-postgres", env="POSTGRES_HOST")
    postgres_port: int = Field(5432, env="POSTGRES_PORT")
    postgres_db: str = Field("sentinel", env="POSTGRES_DB")
    postgres_user: str = Field("sentinel", env="POSTGRES_USER")
    postgres_password: str = Field("", env="POSTGRES_PASSWORD")

    # AI Agents
    ai_agents_port: int = Field(8000, env="AI_AGENTS_PORT")
    ansible_confidence_threshold: float = Field(0.85, env="ANSIBLE_CONFIDENCE_THRESHOLD")

    # Ansible Runner
    ansible_runner_host: str = Field("sentinel-ansible-runner", env="ANSIBLE_RUNNER_HOST")
    ansible_runner_port: int = Field(5001, env="ANSIBLE_RUNNER_PORT")

    # NVD
    nvd_api_key: str = Field("", env="NVD_API_KEY")
    nvd_api_base_url: str = Field("https://services.nvd.nist.gov/rest/json/cves/2.0", env="NVD_API_BASE_URL")

    # ML
    ml_models_path: str = Field("/models", env="ML_MODELS_PATH")
    ml_anomaly_contamination: float = Field(0.05, env="ML_ANOMALY_CONTAMINATION")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

@lru_cache()
def get_settings() -> Settings:
    return Settings()

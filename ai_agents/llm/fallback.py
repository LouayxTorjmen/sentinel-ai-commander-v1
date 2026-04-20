"""
LLM Provider with automatic Groq → Gemini → Ollama failover.

PhD Contribution: Offline resilience ensures the SOC automation platform
remains operational during internet outages or API rate limiting, using
a multi-tier fallback system.
"""
import os
import time
import logging
import requests
import dspy
from dotenv import load_dotenv
load_dotenv()  # Force load from .env

logger = logging.getLogger(__name__)

class LLMProvider:
    """Manages primary (Groq cloud), secondary (Gemini), and fallback (Ollama local) connections."""

    def __init__(self):
        self._groq_api_key = os.getenv("GROQ_API_KEY", "")
        self._groq_model = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
        
        self._gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        _raw = os.getenv("GEMINI_MODEL", "gemini-2.5-flash"); self._gemini_model = _raw.removeprefix("gemini/").removeprefix("models/")

        self._ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://sentinel-ollama:11434")
        self._ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        
        self._temperature = float(os.getenv("LLM_TEMPERATURE", "0"))
        self._max_tokens = int(os.getenv("LLM_MAX_TOKENS", "4096"))
        self._fallback_enabled = os.getenv("LLM_FALLBACK_ENABLED", "true").lower() == "true"

        self._current_provider = "groq"
        self._last_groq_failure = 0.0
        self._last_gemini_failure = 0.0
        self._cooldown = 60

    def _groq_available(self) -> bool:
        if not self._groq_api_key: return False
        if time.monotonic() - self._last_groq_failure < self._cooldown: return False
        try:
            resp = requests.get("https://api.groq.com/openai/v1/models",
                headers={"Authorization": f"Bearer {self._groq_api_key}"}, timeout=5)
            return resp.status_code == 200
        except Exception:
            self._last_groq_failure = time.monotonic()
            return False

    def _gemini_available(self) -> bool:
        if not self._gemini_api_key: return False
        if time.monotonic() - self._last_gemini_failure < self._cooldown: return False
        try:
            resp = requests.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={self._gemini_api_key}", timeout=5)
            return resp.status_code == 200
        except Exception:
            self._last_gemini_failure = time.monotonic()
            return False

    def _ollama_available(self) -> bool:
        try:
            resp = requests.get(f"{self._ollama_base_url}/api/tags", timeout=5)
            if resp.status_code != 200: return False
            models = [m["name"] for m in resp.json().get("models", [])]
            if self._ollama_model not in models and f"{self._ollama_model}:latest" not in models:
                logger.info("ollama.model_not_found, pulling %s", self._ollama_model)
                requests.post(f"{self._ollama_base_url}/api/pull", json={"name": self._ollama_model, "stream": False}, timeout=600)
            return True
        except Exception:
            return False

    def get_lm(self, preferred: str = None) -> dspy.LM:
        if preferred == 'gemini' and self._gemini_available():
            self._current_provider = 'gemini'
            return dspy.LM(model=f'gemini/{self._gemini_model}', api_key=self._gemini_api_key, temperature=self._temperature, max_tokens=self._max_tokens)
        if preferred == 'groq' and self._groq_available():
            self._current_provider = 'groq'
            return dspy.LM(model=f'groq/{self._groq_model}', api_key=self._groq_api_key, temperature=self._temperature, max_tokens=self._max_tokens)
        if self._groq_available():
            self._current_provider = "groq"
            return dspy.LM(model=f"groq/{self._groq_model}", api_key=self._groq_api_key, temperature=self._temperature, max_tokens=self._max_tokens)
        
        if self._gemini_available():
            self._current_provider = "gemini"
            return dspy.LM(model=f"gemini/{self._gemini_model}", api_key=self._gemini_api_key, temperature=self._temperature, max_tokens=self._max_tokens)

        if self._fallback_enabled and self._ollama_available():
            self._current_provider = "ollama"
            return dspy.LM(model=f"ollama_chat/{self._ollama_model}", api_base=self._ollama_base_url, temperature=self._temperature, max_tokens=min(self._max_tokens, 2048))

        self._current_provider = "groq_degraded"
        return dspy.LM(model=f"groq/{self._groq_model}", api_key=self._groq_api_key, temperature=self._temperature, max_tokens=self._max_tokens)

    @property
    def provider(self) -> str:
        return self._current_provider

    def health(self) -> dict:
        return {
            "current_provider": self._current_provider,
            "groq_available": self._groq_available(),
            "gemini_available": self._gemini_available(),
            "ollama_available": self._ollama_available() if self._fallback_enabled else False,
            "fallback_enabled": self._fallback_enabled,
        }

_provider: LLMProvider | None = None
def get_llm_provider() -> LLMProvider:
    global _provider
    if _provider is None: _provider = LLMProvider()
    return _provider

def get_lm(preferred: str = None) -> dspy.LM:
    return get_llm_provider().get_lm(preferred=preferred)

"""
==============================================================================
FILE: apps/api/app/ai/providers/ollama.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Local Ollama HTTP API provider implementation for GASHA.
TOOLS & LIBRARIES: httpx, Pydantic v2, Python standard library (os, time)
KEY FEATURES:
  - OllamaProvider: Connects to local Ollama instance via HTTP API (/api/generate, /api/tags).
  - Enforces JSON output mode (format="json").
  - Configurable via environment variables (OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS).
  - Robust error handling: ConnectionError, TimeoutError, non-200 responses.
EXPECTED RESULTS / BEHAVIOR:
  - Interacts with local open-weights models (Qwen, Ministral, DeepSeek, etc.) without CLI shelling.
==============================================================================
"""

import os
import time
import logging
from typing import Optional, Dict, Any

import httpx

from app.ai.providers.base import (
    AIProvider,
    AIProviderStatus,
    ProviderConfig,
    AIProviderError,
    AIProviderConnectionError,
    AIProviderTimeoutError,
)

logger = logging.getLogger("gasha.ai.providers.ollama")


def get_default_ollama_config() -> ProviderConfig:
    """Constructs default ProviderConfig from environment variables."""
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", os.getenv("AI_MODEL_NAME", "qwen2.5-coder:7b"))
    try:
        timeout = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "30.0"))
    except ValueError:
        timeout = 30.0
    try:
        temperature = float(os.getenv("AI_TEMPERATURE", "0.1"))
    except ValueError:
        temperature = 0.1

    return ProviderConfig(
        provider_name="ollama",
        base_url=base_url,
        model=model,
        timeout_seconds=timeout,
        temperature=temperature,
    )


class OllamaProvider(AIProvider):
    """
    Local Ollama inference adapter communicating directly via Ollama's HTTP REST API.
    """

    def __init__(self, config: Optional[ProviderConfig] = None):
        super().__init__(config or get_default_ollama_config())

    async def generate_investigation(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        format_json: bool = True,
    ) -> str:
        """
        Calls Ollama's /api/generate endpoint with structured JSON enforcement.
        """
        target_model = model or self.config.model
        endpoint = f"{self.config.base_url}/api/generate"

        payload: Dict[str, Any] = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
            },
        }

        if system_prompt:
            payload["system"] = system_prompt

        if format_json:
            payload["format"] = "json"

        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                logger.debug(f"Sending generation request to Ollama ({target_model}) at {endpoint}")
                response = await client.post(endpoint, json=payload)

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code != 200:
                error_msg = f"Ollama HTTP {response.status_code}: {response.text}"
                logger.error(error_msg)
                raise AIProviderError(error_msg)

            data = response.json()
            raw_text = data.get("response", "")
            logger.debug(f"Ollama generation completed in {duration_ms:.1f}ms, response len={len(raw_text)}")
            return raw_text

        except httpx.ConnectError as exc:
            msg = f"Failed to connect to Ollama at {self.config.base_url}: {exc}"
            logger.warning(msg)
            raise AIProviderConnectionError(msg) from exc

        except httpx.TimeoutException as exc:
            msg = f"Ollama request timed out after {self.config.timeout_seconds}s: {exc}"
            logger.warning(msg)
            raise AIProviderTimeoutError(msg) from exc

        except (AIProviderError, AIProviderConnectionError, AIProviderTimeoutError):
            raise

        except Exception as exc:
            msg = f"Unexpected error during Ollama generation: {exc}"
            logger.error(msg)
            raise AIProviderError(msg) from exc

    async def health_check(self) -> AIProviderStatus:
        """
        Queries /api/tags to verify Ollama reachability and check if the configured model is installed.
        """
        endpoint = f"{self.config.base_url}/api/tags"
        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=min(5.0, self.config.timeout_seconds)) as client:
                response = await client.get(endpoint)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code == 200:
                data = response.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                model_installed = any(self.config.model in m or m.startswith(self.config.model.split(":")[0]) for m in models)

                if not model_installed:
                    warning = f"Ollama is reachable, but configured model '{self.config.model}' was not found in tags: {models}"
                    logger.info(warning)

                return AIProviderStatus(
                    provider=self.provider_name,
                    available=True,
                    model=self.config.model,
                    latency_ms=round(latency_ms, 2),
                    error=None if model_installed else f"Model '{self.config.model}' not found in installed models",
                )
            else:
                return AIProviderStatus(
                    provider=self.provider_name,
                    available=False,
                    model=self.config.model,
                    latency_ms=round(latency_ms, 2),
                    error=f"Ollama returned HTTP {response.status_code}",
                )

        except httpx.ConnectError as exc:
            return AIProviderStatus(
                provider=self.provider_name,
                available=False,
                model=self.config.model,
                latency_ms=None,
                error=f"Connection refused at {self.config.base_url}",
            )

        except httpx.TimeoutException as exc:
            return AIProviderStatus(
                provider=self.provider_name,
                available=False,
                model=self.config.model,
                latency_ms=None,
                error=f"Health check timed out after 5.0s",
            )

        except Exception as exc:
            return AIProviderStatus(
                provider=self.provider_name,
                available=False,
                model=self.config.model,
                latency_ms=None,
                error=str(exc),
            )

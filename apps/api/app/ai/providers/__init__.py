"""
GASHA AI Providers Module.

Defines the pluggable provider interface, local Ollama adapter, and registry.
"""

from app.ai.providers.base import (
    AIProvider,
    AIProviderStatus,
    ProviderConfig,
    AIProviderError,
    AIProviderConnectionError,
    AIProviderTimeoutError,
)
from app.ai.providers.ollama import (
    OllamaProvider,
    get_default_ollama_config,
)
from app.ai.providers.registry import (
    ProviderRegistry,
    register_provider,
    get_provider,
    get_default_provider,
)

__all__ = [
    "AIProvider",
    "AIProviderStatus",
    "ProviderConfig",
    "AIProviderError",
    "AIProviderConnectionError",
    "AIProviderTimeoutError",
    "OllamaProvider",
    "get_default_ollama_config",
    "ProviderRegistry",
    "register_provider",
    "get_provider",
    "get_default_provider",
]

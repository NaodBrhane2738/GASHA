"""
==============================================================================
FILE: apps/api/app/ai/providers/registry.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Pluggable registry for resolving and instantiating AI providers in GASHA.
TOOLS & LIBRARIES: Python standard library
KEY FEATURES:
  - ProviderRegistry: Thread-safe singleton mapping provider names to factory/classes.
  - register_provider(), get_provider(), get_default_provider()
EXPECTED RESULTS / BEHAVIOR:
  - Supports dynamic registration and provider swapping via AI_PROVIDER environment variable.
==============================================================================
"""

import os
import logging
from typing import Dict, Type, Optional, Callable

from app.ai.providers.base import AIProvider, ProviderConfig, AIProviderError
from app.ai.providers.ollama import OllamaProvider, get_default_ollama_config

logger = logging.getLogger("gasha.ai.providers.registry")

ProviderFactory = Callable[[Optional[ProviderConfig]], AIProvider]


class ProviderRegistry:
    """Registry maintaining available AI provider implementations."""

    def __init__(self):
        self._providers: Dict[str, ProviderFactory] = {}
        # Register default local providers
        self.register("ollama", lambda cfg: OllamaProvider(cfg or get_default_ollama_config()))

    def register(self, name: str, factory: ProviderFactory) -> None:
        """Registers a provider name with its instantiation factory."""
        self._providers[name.lower()] = factory
        logger.debug(f"Registered AI provider: {name}")

    def get(self, name: str, config: Optional[ProviderConfig] = None) -> AIProvider:
        """Retrieves and instantiates an AI provider by name."""
        key = name.lower()
        if key not in self._providers:
            available = list(self._providers.keys())
            raise AIProviderError(f"AI provider '{name}' is not registered. Available providers: {available}")
        return self._providers[key](config)

    def list_available(self) -> list[str]:
        """Lists all registered provider identifiers."""
        return list(self._providers.keys())


# Global registry instance
_registry = ProviderRegistry()


def register_provider(name: str, factory: ProviderFactory) -> None:
    """Registers a provider in the global registry."""
    _registry.register(name, factory)


def get_provider(name: str, config: Optional[ProviderConfig] = None) -> AIProvider:
    """Retrieves an instantiated provider from the global registry."""
    return _registry.get(name, config)


def get_default_provider() -> AIProvider:
    """
    Resolves and instantiates the configured default provider from environment.
    Defaults to 'ollama'.
    """
    provider_name = os.getenv("AI_PROVIDER", "ollama").lower()
    return _registry.get(provider_name)

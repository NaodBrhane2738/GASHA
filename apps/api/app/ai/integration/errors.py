"""
==============================================================================
FILE: apps/api/app/ai/integration/errors.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Integration-specific exceptions for the GASHA AI service boundary.
==============================================================================
"""

class AIIntegrationError(Exception):
    """Base exception for all AI integration layer errors."""
    pass


class InvalidContextError(AIIntegrationError):
    """Raised when an incoming InvestigationContext payload fails structural validation."""
    pass


class UnsupportedContextVersionError(AIIntegrationError):
    """Raised when an incoming context specifies an unsupported context_version."""
    def __init__(self, version: str, supported: set):
        self.version = version
        self.supported = supported
        super().__init__(
            f"Unsupported context version '{version}'. Supported versions are: {sorted(list(supported))}"
        )


class AIUnavailableError(AIIntegrationError):
    """Raised when the underlying local AI provider (Ollama) is offline or unreachable."""
    pass


class AITimeoutError(AIIntegrationError):
    """Raised when AI inference exceeds the allowed execution time budget."""
    pass


class InvalidAIOutputError(AIIntegrationError):
    """Raised when the raw AI model output cannot be parsed into a valid structured schema."""
    pass


class GroundingFailureError(AIIntegrationError):
    """Raised when an AI investigation cites non-existent evidence or unverified assets."""
    pass

"""
GASHA AI Subsystem — Integration Package.
Exposes stable production entry points, mapping utilities, and error classes.
"""

from app.ai.integration.adapter import (
    investigate_incident,
    ainvestigate_incident,
    run_ai_investigation,
    run_ai_investigation_sync,
    is_context_stale,
)
from app.ai.integration.mapper import (
    map_backend_dict_to_context,
    format_recommendation_for_backend,
    map_to_backend_investigation_response,
)
from app.ai.integration.errors import (
    AIIntegrationError,
    InvalidContextError,
    UnsupportedContextVersionError,
    AIUnavailableError,
    AITimeoutError,
    InvalidAIOutputError,
    GroundingFailureError,
)

__all__ = [
    # Primary Entry Points
    "investigate_incident",
    "ainvestigate_incident",
    "run_ai_investigation",
    "run_ai_investigation_sync",
    "is_context_stale",
    # Mapper
    "map_backend_dict_to_context",
    "format_recommendation_for_backend",
    "map_to_backend_investigation_response",
    # Errors
    "AIIntegrationError",
    "InvalidContextError",
    "UnsupportedContextVersionError",
    "AIUnavailableError",
    "AITimeoutError",
    "InvalidAIOutputError",
    "GroundingFailureError",
]

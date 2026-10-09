"""
GASHA Telemetry SDK for Python applications.

High-performance, non-blocking telemetry emitter and ASGI middleware
for deterministic security monitoring in the GASHA defensive platform.
"""

try:
    from .models import (
        TelemetryEventType,
        TelemetryEventPayload,
        TelemetryEvent,
        TelemetryBatch,
    )
    from .sanitizers import (
        sanitize_metadata,
        sanitize_headers,
        mask_token,
    )
    from .client import (
        TelemetryClient,
        TelemetryClientConfig,
    )
    from .middleware import (
        GashaTelemetryMiddleware,
    )
    from .gasha_telemetry import (
        GashaTelemetry,
        init_telemetry,
        get_telemetry,
    )
except (ImportError, ValueError):
    from models import (
        TelemetryEventType,
        TelemetryEventPayload,
        TelemetryEvent,
        TelemetryBatch,
    )
    from sanitizers import (
        sanitize_metadata,
        sanitize_headers,
        mask_token,
    )
    from client import (
        TelemetryClient,
        TelemetryClientConfig,
    )
    from middleware import (
        GashaTelemetryMiddleware,
    )
    from gasha_telemetry import (
        GashaTelemetry,
        init_telemetry,
        get_telemetry,
    )

__all__ = [
    "TelemetryEventType",
    "TelemetryEventPayload",
    "TelemetryEvent",
    "TelemetryBatch",
    "sanitize_metadata",
    "sanitize_headers",
    "mask_token",
    "TelemetryClient",
    "TelemetryClientConfig",
    "GashaTelemetryMiddleware",
    "GashaTelemetry",
    "init_telemetry",
    "get_telemetry",
]

"""
==============================================================================
FILE: apps/api/app/telemetry/validator.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Validates telemetry events against strict schema rules and sanity constraints.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - validate_telemetry_event(raw_event: dict) -> bool
EXPECTED RESULTS / BEHAVIOR:
  - Rejects malformed or spoofed telemetry events prior to detection evaluation.
==============================================================================
"""

from app.schemas.telemetry import TelemetryEventSchema

def validate_event(event: TelemetryEventSchema) -> bool:
    return bool(event.id and event.eventType and event.timestamp)

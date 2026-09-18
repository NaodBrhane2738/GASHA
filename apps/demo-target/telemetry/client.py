"""
==============================================================================
FILE: apps/demo-target/telemetry/client.py
ROLE / OWNERSHIP: Full Team (Demo Target Instrumentation)
OBJECTIVE: Configures the GASHA Telemetry SDK instance for the demo target application.
TOOLS & LIBRARIES: packages.telemetry_sdk.python.gasha_telemetry
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - telemetry_client: Initialized instance with target service credentials.
EXPECTED RESULTS / BEHAVIOR:
  - Provides a shared client to emit genuine runtime events to GASHA backend.
==============================================================================
"""

from packages.telemetry_sdk.python.gasha_telemetry import GashaTelemetryClient

telemetry_client = GashaTelemetryClient(
    endpoint="http://localhost:4000/api/v1/telemetry/ingest",
    api_key="gasha-telemetry-demo-key-2026",
    environment_id="env-demo-target",
    service_name="demo-target-web-api"
)

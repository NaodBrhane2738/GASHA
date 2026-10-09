"""
==============================================================================
FILE: apps/demo-target/telemetry/client.py
ROLE / OWNERSHIP: Full Team (Demo Target Instrumentation)
OBJECTIVE: Configures the GASHA Telemetry SDK instance for the demo target application.
==============================================================================
"""

import os
import sys
import pathlib

# Ensure telemetry-sdk is discoverable
try:
    from packages.telemetry_sdk.python.gasha_telemetry import GashaTelemetry
except (ImportError, ValueError):
    try:
        from gasha_telemetry import GashaTelemetry
    except (ImportError, ValueError):
        current_file = pathlib.Path(__file__).resolve()
        root_dir = current_file.parent.parent.parent.parent
        sdk_path = root_dir / "packages" / "telemetry-sdk" / "python"
        if str(sdk_path) not in sys.path:
            sys.path.insert(0, str(sdk_path))
        from gasha_telemetry import GashaTelemetry


telemetry_client = GashaTelemetry(
    endpoint=os.getenv("GASHA_TELEMETRY_ENDPOINT", "http://localhost:4000/api/v1/telemetry/ingest"),
    api_key=os.getenv("GASHA_TELEMETRY_API_KEY", "gasha-telemetry-demo-key-2026"),
    environment_id=os.getenv("GASHA_TELEMETRY_ENVIRONMENT", "env-prod"),
    service_name="demo-target-web-api",
    flush_interval_seconds=0.2  # Fast batch dispatch for responsive test/demo feedback
)

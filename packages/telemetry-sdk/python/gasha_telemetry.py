"""
==============================================================================
FILE: packages/telemetry-sdk/python/gasha_telemetry.py
ROLE / OWNERSHIP: Shared Telemetry SDK Maintainers
OBJECTIVE: Provide lightweight, non-blocking Python instrumentation client.
TOOLS & LIBRARIES: Python 3.11+, requests / httpx, asyncio
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - class GashaTelemetryClient:
      - __init__(endpoint, api_key, environment_id, service_name, batch_size=20)
      - emit(event_type: str, payload: dict) -> None
      - flush() -> None
      - fastapi_middleware() -> ASGI middleware for automatic request logging
EXPECTED RESULTS / BEHAVIOR:
  - Emits structured telemetry events to GASHA backend API asynchronously without blocking app execution.
==============================================================================
"""

import time
import uuid
import logging
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("gasha_telemetry")

class GashaTelemetryClient:
    def __init__(
        self,
        endpoint: str,
        api_key: str,
        environment_id: str = "env-prod",
        service_name: str = "python-service",
        batch_size: int = 20,
        flush_interval_seconds: float = 2.0
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.environment_id = environment_id
        self.service_name = service_name
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.queue: List[Dict[str, Any]] = []

    def emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Buffers a single telemetry event."""
        event = {
            "id": f"telem-{uuid.uuid4()}",
            "eventType": event_type,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sourceService": self.service_name,
            "environmentId": self.environment_id,
            "payload": payload
        }
        self.queue.append(event)
        if len(self.queue) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        """Flushes buffered events to the GASHA Ingestion API."""
        if not self.queue:
            return
        batch = list(self.queue)
        self.queue.clear()
        try:
            with httpx.Client(timeout=3.0) as client:
                client.post(
                    self.endpoint,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json={"events": batch}
                )
        except Exception as e:
            logger.error(f"[GASHA SDK] Failed to flush telemetry batch: {e}")

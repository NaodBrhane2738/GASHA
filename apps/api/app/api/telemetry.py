"""
==============================================================================
FILE: apps/api/app/api/telemetry.py
ROLE / OWNERSHIP: Backend & Telemetry Engineers
OBJECTIVE: High-throughput ingestion endpoint for runtime events from target applications.
TOOLS & LIBRARIES: FastAPI APIRouter, app.schemas.telemetry, app.telemetry.ingester
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - POST /api/v1/telemetry/ingest: Receives batch telemetry from @gasha/telemetry-sdk.
  - Authenticates via X-GASHA-TELEMETRY-KEY or Bearer token.
  - Dispatches validated events into the Detection Engine queue asynchronously.
EXPECTED RESULTS / BEHAVIOR:
  - Immediate HTTP 202 Accepted response; zero blocking of target application execution.
==============================================================================
"""

from fastapi import APIRouter, Depends, Request, status
from app.core.auth import verify_telemetry_api_key
from app.core.events import utc_iso
from app.schemas.telemetry import TelemetryBatchIngestRequest
from app.telemetry.validator import validate_event

router = APIRouter()

@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_telemetry_batch(
    batch: TelemetryBatchIngestRequest,
    request: Request,
    authenticated: bool = Depends(verify_telemetry_api_key)
):
    pipeline = request.app.state.soc.pipeline
    enforcement = {}
    processed = 0
    for event in batch.events:
        if not validate_event(event):
            continue
        processed += 1
        decision = pipeline.observe_telemetry(event)
        if decision and decision.action in ("THROTTLE", "LOCK"):
            # The defended app applies these decisions (e.g. demo-target blocklist).
            enforcement[decision.sourceKey] = decision.model_dump(
                include={"action", "statusCode", "ruleId", "retryAfterSeconds", "sourceKey"})
    return {
        "status": "ACCEPTED",
        "eventsProcessed": processed,
        "enforcement": list(enforcement.values()),
        "timestamp": utc_iso(),
    }

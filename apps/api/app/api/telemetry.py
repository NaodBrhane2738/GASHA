"""
==============================================================================
FILE: apps/api/app/api/telemetry.py
ROLE / OWNERSHIP: Backend & Telemetry Engineers
OBJECTIVE: High-throughput ingestion endpoint for runtime events from target applications.
TOOLS & LIBRARIES: FastAPI APIRouter, app.schemas.telemetry, app.telemetry.ingester
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - POST /api/v1/telemetry/ingest: Receives batch telemetry from @gasha/telemetry-sdk.
  - Authenticates via X-GASHA-TELEMETRY-KEY or Bearer token.
  - Validates batch constraints (size, schemas, timestamp sanity, environment isolation).
  - Enqueues into bounded buffer asynchronously without blocking caller execution.
  - GET /api/v1/telemetry/health: Pipeline health status and buffer capacity.
  - GET /api/v1/telemetry/metrics: Operational counters and telemetry ingestion metrics.
==============================================================================
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.config import settings
from app.core.auth import verify_telemetry_api_key
from app.schemas.telemetry import (
    TelemetryBatchIngestRequest,
    TelemetryBatchIngestResponse,
)
from app.telemetry.ingester import enqueue_batch, get_telemetry_ingester

router = APIRouter()


@router.post(
    "/ingest",
    response_model=TelemetryBatchIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest Telemetry Batch",
    description="High-throughput asynchronous ingestion endpoint for runtime security telemetry events."
)
async def ingest_telemetry_batch(
    batch: TelemetryBatchIngestRequest,
    auth_ctx: dict = Depends(verify_telemetry_api_key)
) -> TelemetryBatchIngestResponse:
    if not batch.events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch contains no telemetry events"
        )

    max_batch_size = getattr(settings, "MAX_BATCH_SIZE", 100)
    if len(batch.events) > max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size of {len(batch.events)} exceeds maximum limit of {max_batch_size} events"
        )

    authorized_env = auth_ctx.get("environmentId")
    response = await enqueue_batch(batch.events, authorized_environment=authorized_env)
    import asyncio
    from app.telemetry.processor import process_stream
    asyncio.create_task(process_stream(batch.events))
    return response


@router.get(
    "/health",
    summary="Telemetry Pipeline Health",
    description="Operational health status of the ingestion pipeline and buffer."
)
async def telemetry_health() -> Dict[str, Any]:
    metrics = get_telemetry_ingester().get_metrics()
    is_healthy = metrics["queue_depth"] < metrics["buffer_capacity"]
    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": "gasha-telemetry-ingestion",
        "queueDepth": metrics["queue_depth"],
        "bufferCapacity": metrics["buffer_capacity"],
        "droppedOverflow": metrics["events_dropped_overflow"],
    }


@router.get(
    "/metrics",
    summary="Telemetry Pipeline Metrics",
    description="Telemetry ingestion counters and operational metrics."
)
async def telemetry_metrics() -> Dict[str, Any]:
    return get_telemetry_ingester().get_metrics()

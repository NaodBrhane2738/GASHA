"""
==============================================================================
FILE: apps/api/app/schemas/telemetry.py
ROLE / OWNERSHIP: Backend Engineers & Telemetry Pipeline Maintainers
OBJECTIVE: Pydantic schemas for Telemetry event ingestion and batching.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - TelemetryEventPayloadSchema: Key metadata fields (source IP, path, user, session, etc.).
  - TelemetryEventSchema: Complete individual event representation.
  - TelemetryBatchIngestRequest: Batch payload emitted by @gasha/telemetry-sdk.
EXPECTED RESULTS / BEHAVIOR:
  - Validates and ingests high-throughput telemetry streams from target applications.
==============================================================================
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

TelemetryEventType = Literal[
    'AUTH_FAILURE',
    'AUTH_SUCCESS',
    'HTTP_REQUEST',
    'SUSPICIOUS_REQUEST',
    'RESOURCE_ACCESS',
    'PRIVILEGE_CHANGE',
    'OUTBOUND_CONNECTION'
]

class TelemetryEventPayloadSchema(BaseModel):
    sourceIp: Optional[str] = None
    observedPeerIp: Optional[str] = None
    userAgent: Optional[str] = None
    userId: Optional[str] = None
    sessionId: Optional[str] = None
    httpMethod: Optional[str] = None
    httpPath: Optional[str] = None
    httpStatusCode: Optional[int] = None
    resourceAccessed: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    latencyMs: Optional[float] = None
    correlationId: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class TelemetryEventSchema(BaseModel):
    id: str
    schemaVersion: Optional[str] = "1.0.0"
    eventType: TelemetryEventType
    timestamp: str
    sourceService: str
    environmentId: str
    payload: TelemetryEventPayloadSchema

class TelemetryBatchIngestRequest(BaseModel):
    events: List[TelemetryEventSchema]

class TelemetryItemResult(BaseModel):
    id: str
    status: Literal['accepted', 'duplicate', 'rejected', 'failed']
    reason: Optional[str] = None

class TelemetryBatchIngestResponse(BaseModel):
    status: Literal['ACCEPTED', 'PARTIALLY_ACCEPTED', 'REJECTED']
    acceptedCount: int
    rejectedCount: int
    duplicateCount: int
    totalCount: int
    results: List[TelemetryItemResult]
    timestamp: str
    eventsProcessed: int = 0  # Backward-compatible alias for acceptedCount

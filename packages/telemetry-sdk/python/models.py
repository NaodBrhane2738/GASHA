"""
GASHA Telemetry Data Contracts & Event Models
Defines structured, versioned event schemas conforming to @gasha/contracts.
"""
from enum import Enum
from typing import Optional, Dict, Any, List, Union
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field, ConfigDict

class TelemetryEventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    HTTP_REQUEST = "HTTP_REQUEST"
    SUSPICIOUS_REQUEST = "SUSPICIOUS_REQUEST"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    OUTBOUND_CONNECTION = "OUTBOUND_CONNECTION"

class TelemetryEventPayload(BaseModel):
    """Normalized payload of a single telemetry event."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    source_ip: Optional[str] = Field(default=None, alias="sourceIp")
    observed_peer_ip: Optional[str] = Field(default=None, alias="observedPeerIp")
    user_agent: Optional[str] = Field(default=None, alias="userAgent")
    user_id: Optional[str] = Field(default=None, alias="userId")
    session_id: Optional[str] = Field(default=None, alias="sessionId")
    http_method: Optional[str] = Field(default=None, alias="httpMethod")
    http_path: Optional[str] = Field(default=None, alias="httpPath")
    http_status_code: Optional[int] = Field(default=None, alias="httpStatusCode")
    resource_accessed: Optional[str] = Field(default=None, alias="resourceAccessed")
    action: Optional[str] = None
    outcome: Optional[str] = None
    latency_ms: Optional[float] = Field(default=None, alias="latencyMs")
    correlation_id: Optional[str] = Field(default=None, alias="correlationId")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def sourceIp(self) -> Optional[str]:
        return self.source_ip

    @property
    def userId(self) -> Optional[str]:
        return self.user_id

    @property
    def sessionId(self) -> Optional[str]:
        return self.session_id

    @property
    def httpMethod(self) -> Optional[str]:
        return self.http_method

    @property
    def httpPath(self) -> Optional[str]:
        return self.http_path

    @property
    def httpStatusCode(self) -> Optional[int]:
        return self.http_status_code

    @property
    def resourceAccessed(self) -> Optional[str]:
        return self.resource_accessed

class TelemetryEvent(BaseModel):
    """
    Standard structured security telemetry event record conforming to GASHA contracts.
    Must never contain unredacted secrets or bearer tokens.
    """
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: str = Field(default_factory=lambda: f"telem-{uuid.uuid4().hex[:12]}")
    schema_version: str = Field(default="1.0.0", alias="schemaVersion")
    event_type: TelemetryEventType = Field(alias="eventType")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_service: str = Field(default="python-service", alias="sourceService")
    environment_id: str = Field(default="env-prod", alias="environmentId")
    payload: TelemetryEventPayload

    @property
    def eventType(self) -> TelemetryEventType:
        return self.event_type

    @property
    def sourceService(self) -> str:
        return self.source_service

    @property
    def environmentId(self) -> str:
        return self.environment_id

    @property
    def schemaVersion(self) -> str:
        return self.schema_version

class SDKDeliveryMetrics(BaseModel):
    """Observable operational metrics for the SDK client."""
    model_config = ConfigDict(populate_by_name=True)

    queued_count: int = 0
    transmitted_count: int = 0
    dropped_count: int = 0
    error_count: int = 0
    retry_count: int = 0
    last_flush_time: Optional[str] = None
    is_running: bool = False

class TelemetryBatch(BaseModel):
    """Batch of telemetry events submitted for ingestion."""
    model_config = ConfigDict(populate_by_name=True)
    events: List[TelemetryEvent]

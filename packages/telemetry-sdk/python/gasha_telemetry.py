"""
GASHA Telemetry SDK Facade
High-level, developer-friendly instrumentation interface for Python server applications.
Provides structured security event emitters, singleton management, and ASGI middleware bindings.
"""
import uuid
import time
from typing import Optional, Dict, Any, Union
from datetime import datetime, timezone

try:
    from .models import (
        TelemetryEvent, TelemetryEventType, TelemetryEventPayload, SDKDeliveryMetrics
    )
    from .client import TelemetryClient
    from .sanitizers import sanitize_metadata
except (ImportError, ValueError):
    from models import (
        TelemetryEvent, TelemetryEventType, TelemetryEventPayload, SDKDeliveryMetrics
    )
    from client import TelemetryClient
    from sanitizers import sanitize_metadata

class GashaTelemetry:
    """
    Primary developer API for manual and automated security telemetry emission.
    """
    def __init__(
        self,
        endpoint: str = "http://localhost:4000/api/v1/telemetry/ingest",
        api_key: str = "gasha-telemetry-demo-key-2026",
        environment_id: str = "env-prod",
        service_name: str = "python-service",
        max_queue_size: int = 2000,
        batch_size: int = 20,
        flush_interval_seconds: float = 1.0,
        http_timeout_seconds: float = 3.0,
        max_retries: int = 3,
        auto_start: bool = True
    ):
        self.endpoint = endpoint
        self.api_key = api_key
        self.environment_id = environment_id
        self.service_name = service_name
        self.client = TelemetryClient(
            endpoint=endpoint,
            api_key=api_key,
            environment_id=environment_id,
            service_name=service_name,
            max_queue_size=max_queue_size,
            batch_size=batch_size,
            flush_interval_seconds=flush_interval_seconds,
            http_timeout_seconds=http_timeout_seconds,
            max_retries=max_retries,
            auto_start=auto_start
        )

    def emit(
        self,
        event_type: Union[TelemetryEventType, str],
        payload: Union[TelemetryEventPayload, Dict[str, Any]],
        event_id: Optional[str] = None
    ) -> TelemetryEvent:
        """Generic structured event emitter."""
        ev_type = TelemetryEventType(event_type) if isinstance(event_type, str) else event_type
        
        if isinstance(payload, dict):
            clean_meta = sanitize_metadata(payload.get("metadata", {}))
            payload_obj = TelemetryEventPayload(
                sourceIp=payload.get("sourceIp") or payload.get("source_ip"),
                observedPeerIp=payload.get("observedPeerIp") or payload.get("observed_peer_ip"),
                userAgent=payload.get("userAgent") or payload.get("user_agent"),
                userId=payload.get("userId") or payload.get("user_id"),
                sessionId=payload.get("sessionId") or payload.get("session_id"),
                httpMethod=payload.get("httpMethod") or payload.get("http_method"),
                httpPath=payload.get("httpPath") or payload.get("http_path"),
                httpStatusCode=payload.get("httpStatusCode") or payload.get("http_status_code"),
                resourceAccessed=payload.get("resourceAccessed") or payload.get("resource_accessed"),
                action=payload.get("action"),
                outcome=payload.get("outcome"),
                latencyMs=payload.get("latencyMs") or payload.get("latency_ms"),
                correlationId=payload.get("correlationId") or payload.get("correlation_id"),
                metadata=clean_meta
            )
        else:
            payload_obj = payload

        event = TelemetryEvent(
            id=event_id or f"telem-{uuid.uuid4().hex[:12]}",
            schemaVersion="1.0.0",
            eventType=ev_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sourceService=self.service_name,
            environmentId=self.environment_id,
            payload=payload_obj
        )
        self.client.enqueue(event)
        return event

    def auth_failure(
        self,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        reason: str = "INVALID_CREDENTIALS",
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        action: str = "LOGIN",
        outcome: str = "FAILURE"
    ) -> TelemetryEvent:
        """Logs an authentication failure (e.g. bad password, nonexistent user)."""
        meta = metadata.copy() if metadata else {}
        meta["failure_reason"] = reason
        payload = TelemetryEventPayload(
            sourceIp=source_ip,
            userId=user_id,
            userAgent=user_agent,
            action=action,
            outcome=outcome,
            metadata=sanitize_metadata(meta)
        )
        return self.emit(TelemetryEventType.AUTH_FAILURE, payload)

    def auth_success(
        self,
        source_ip: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        action: str = "LOGIN",
        outcome: str = "SUCCESS"
    ) -> TelemetryEvent:
        """Logs a successful authentication (login, token refresh)."""
        payload = TelemetryEventPayload(
            sourceIp=source_ip,
            userId=user_id,
            sessionId=session_id,
            userAgent=user_agent,
            action=action,
            outcome=outcome,
            metadata=sanitize_metadata(metadata or {})
        )
        return self.emit(TelemetryEventType.AUTH_SUCCESS, payload)

    def http_request(
        self,
        method: str,
        path: str,
        status_code: int,
        source_ip: Optional[str] = None,
        latency_ms: Optional[float] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TelemetryEvent:
        """Logs a standard HTTP transaction."""
        payload = TelemetryEventPayload(
            sourceIp=source_ip,
            userId=user_id,
            sessionId=session_id,
            httpMethod=method,
            httpPath=path,
            httpStatusCode=status_code,
            resourceAccessed=path,
            action="HTTP_TRANSACTION",
            outcome="SUCCESS" if status_code < 400 else "ERROR",
            latencyMs=latency_ms,
            metadata=sanitize_metadata(metadata or {})
        )
        return self.emit(TelemetryEventType.HTTP_REQUEST, payload)

    def suspicious_request(
        self,
        source_ip: Optional[str] = None,
        path: str = "",
        threat_type: str = "INJECTION_PROBE",
        details: Optional[Dict[str, Any]] = None
    ) -> TelemetryEvent:
        """Logs a suspicious request probe (SQLi, XSS, Path Traversal)."""
        meta = details.copy() if details else {}
        meta["threat_type"] = threat_type
        payload = TelemetryEventPayload(
            sourceIp=source_ip,
            httpPath=path,
            resourceAccessed=path,
            action=f"SUSPICIOUS_PROBE_{threat_type}",
            outcome="DETECTED_PASSIVE",
            metadata=sanitize_metadata(meta)
        )
        return self.emit(TelemetryEventType.SUSPICIOUS_REQUEST, payload)

    def resource_access(
        self,
        resource_id: str,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        action: str = "READ",
        granted: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TelemetryEvent:
        """Logs an access control or authorization boundary check on a critical asset."""
        meta = metadata.copy() if metadata else {}
        meta["access_granted"] = granted
        payload = TelemetryEventPayload(
            sourceIp=source_ip,
            userId=user_id,
            resourceAccessed=resource_id,
            action=action,
            outcome="GRANTED" if granted else "DENIED",
            metadata=sanitize_metadata(meta)
        )
        return self.emit(TelemetryEventType.RESOURCE_ACCESS, payload)

    def privilege_change(
        self,
        user_id: Optional[str] = None,
        previous_role: Optional[str] = None,
        new_role: str = "",
        source_ip: Optional[str] = None,
        performed_by: Optional[str] = None,
        target_user_id: Optional[str] = None,
        actor_user_id: Optional[str] = None,
        old_role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TelemetryEvent:
        """Logs a user role modification or privilege boundary elevation."""
        target_uid = target_user_id or user_id or "unknown"
        actor_uid = actor_user_id or performed_by
        prev_r = old_role or previous_role
        meta = metadata.copy() if metadata else {}
        if prev_r:
            meta["old_role"] = prev_r
            meta["previous_role"] = prev_r
        meta["new_role"] = new_role
        if actor_uid:
            meta["actor_user_id"] = actor_uid
            meta["performed_by"] = actor_uid
        payload = TelemetryEventPayload(
            sourceIp=source_ip,
            userId=target_uid,
            action="ROLE_MUTATION",
            outcome="UPDATED",
            metadata=sanitize_metadata(meta)
        )
        return self.emit(TelemetryEventType.PRIVILEGE_CHANGE, payload)

    def outbound_connection(
        self,
        destination: Optional[str] = None,
        port: Optional[int] = None,
        protocol: str = "TCP",
        target_host: Optional[str] = None,
        target_port: Optional[int] = None,
        source_service: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> TelemetryEvent:
        """Logs an egress / outbound network communication."""
        host = target_host or destination or "unknown"
        p = target_port if target_port is not None else (port if port is not None else 0)
        meta = metadata.copy() if metadata else {}
        meta["protocol"] = protocol
        meta["destination_port"] = p
        payload = TelemetryEventPayload(
            resourceAccessed=f"{host}:{p}",
            action="OUTBOUND_CONNECT",
            outcome="INITIATED",
            metadata=sanitize_metadata(meta)
        )
        return self.emit(TelemetryEventType.OUTBOUND_CONNECTION, payload)

    def flush(self, timeout: float = 3.0) -> None:
        """Flushes buffered events to the backend."""
        self.client.flush(timeout=timeout)

    def close(self, timeout: float = 2.0) -> None:
        """Closes the client and background worker."""
        self.client.close(timeout=timeout)

    def shutdown(self, timeout: float = 2.0) -> None:
        """Gracefully flushes and closes."""
        self.client.shutdown(timeout=timeout)

    def get_metrics(self) -> SDKDeliveryMetrics:
        """Returns delivery health counters."""
        return self.client.get_metrics()

# Backward-compatible class alias
GashaTelemetryClient = GashaTelemetry

# Global singleton management
_global_telemetry: Optional[GashaTelemetry] = None

def init_telemetry(**kwargs) -> GashaTelemetry:
    """Initializes global telemetry singleton."""
    global _global_telemetry
    _global_telemetry = GashaTelemetry(**kwargs)
    return _global_telemetry

def get_telemetry() -> GashaTelemetry:
    """Retrieves or auto-initializes the global telemetry instance."""
    global _global_telemetry
    if _global_telemetry is None:
        _global_telemetry = GashaTelemetry()
    return _global_telemetry

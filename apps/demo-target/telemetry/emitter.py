"""
==============================================================================
FILE: apps/demo-target/telemetry/emitter.py
ROLE / OWNERSHIP: Full Team (Demo Target Instrumentation)
OBJECTIVE: Helper functions to emit structured security telemetry during application workflows.
==============================================================================
"""

from typing import Optional, Dict, Any

try:
    from apps.demo_target.telemetry.client import telemetry_client
except ImportError:
    from .client import telemetry_client


def emit_auth_failure(source_ip: str, user_id: str, reason: str = "BAD_CREDENTIALS"):
    """Emits AUTH_FAILURE event."""
    telemetry_client.emit("AUTH_FAILURE", {
        "sourceIp": source_ip,
        "userId": user_id,
        "outcome": "DENIED",
        "metadata": {"reason": reason}
    })


def emit_auth_success(source_ip: str, user_id: str, session_id: str):
    """Emits AUTH_SUCCESS event."""
    telemetry_client.emit("AUTH_SUCCESS", {
        "sourceIp": source_ip,
        "userId": user_id,
        "sessionId": session_id,
        "outcome": "ALLOWED",
        "metadata": {"sessionId": session_id}
    })


def emit_http_request(
    source_ip: str,
    method: str,
    path: str,
    status_code: int,
    user_id: Optional[str] = None
):
    """Emits HTTP_REQUEST event."""
    telemetry_client.emit("HTTP_REQUEST", {
        "sourceIp": source_ip,
        "userId": user_id,
        "httpMethod": method,
        "httpPath": path,
        "httpStatusCode": status_code,
        "outcome": "ALLOWED" if status_code < 400 else "DENIED"
    })


def emit_suspicious_request(
    source_ip: str,
    path: str,
    pattern_type: str,
    user_id: Optional[str] = None,
    raw_query: Optional[str] = None
):
    """Emits SUSPICIOUS_REQUEST event with pattern indicators."""
    telemetry_client.emit("SUSPICIOUS_REQUEST", {
        "sourceIp": source_ip,
        "userId": user_id,
        "httpPath": path,
        "outcome": "FLAGGED",
        "metadata": {
            "pattern_type": pattern_type,
            "suspicious_tags": [pattern_type],
            "rawQuery": raw_query
        }
    })


def emit_resource_access(
    source_ip: str,
    user_id: str,
    resource_id: str,
    outcome: str = "ALLOWED"
):
    """Emits RESOURCE_ACCESS event."""
    telemetry_client.emit("RESOURCE_ACCESS", {
        "sourceIp": source_ip,
        "userId": user_id,
        "resourceId": resource_id,
        "outcome": outcome,
        "metadata": {"resource": resource_id}
    })


def emit_privilege_change(
    source_ip: str,
    user_id: str,
    old_role: str,
    new_role: str,
    outcome: str = "UPDATED"
):
    """Emits PRIVILEGE_CHANGE event."""
    telemetry_client.emit("PRIVILEGE_CHANGE", {
        "sourceIp": source_ip,
        "userId": user_id,
        "outcome": outcome,
        "metadata": {
            "old_role": old_role,
            "new_role": new_role
        }
    })


def flush_telemetry():
    """Forces immediate queue flush to ingestion API."""
    if hasattr(telemetry_client, "flush"):
        telemetry_client.flush()

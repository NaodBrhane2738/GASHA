"""
==============================================================================
FILE: apps/demo-target/telemetry/emitter.py
ROLE / OWNERSHIP: Full Team (Demo Target Instrumentation)
OBJECTIVE: Helper functions to emit specific telemetry events during application workflows.
TOOLS & LIBRARIES: apps.demo_target.telemetry.client
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - emit_auth_failure(source_ip, user_id, reason)
  - emit_auth_success(source_ip, user_id, session_id)
  - emit_resource_access(source_ip, user_id, resource_id)
EXPECTED RESULTS / BEHAVIOR:
  - Clean API wrapper called by demo target route handlers when user actions occur.
==============================================================================
"""

from apps.demo_target.telemetry.client import telemetry_client

def emit_auth_failure(source_ip: str, user_id: str, reason: str = "BAD_CREDENTIALS"):
    telemetry_client.emit("AUTH_FAILURE", {
        "sourceIp": source_ip,
        "userId": user_id,
        "metadata": {"reason": reason}
    })

def emit_auth_success(source_ip: str, user_id: str, session_id: str):
    telemetry_client.emit("AUTH_SUCCESS", {
        "sourceIp": source_ip,
        "userId": user_id,
        "sessionId": session_id
    })

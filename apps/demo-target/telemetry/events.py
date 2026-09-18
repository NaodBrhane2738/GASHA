"""
==============================================================================
FILE: apps/demo-target/telemetry/events.py
ROLE / OWNERSHIP: Full Team (Demo Target Instrumentation)
OBJECTIVE: Event constants and event shape definitions used within the demo application.
TOOLS & LIBRARIES: Python enum
==============================================================================
"""

class TargetEventType:
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    HTTP_REQUEST = "HTTP_REQUEST"
    SUSPICIOUS_REQUEST = "SUSPICIOUS_REQUEST"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"

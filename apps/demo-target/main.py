"""
==============================================================================
FILE: apps/demo-target/main.py
ROLE / OWNERSHIP: Full Team (Demo Target Defenses & Simulation)
OBJECTIVE: Controlled, instrumented Demo Target Application for GASHA.
           Implements realistic web service endpoints, security middleware,
           server-side telemetry emission via GASHA SDK, and controlled active defense.
==============================================================================
"""

import re
import uuid
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, Request, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

try:
    from apps.demo_target.security.middleware import SecurityEnforcementMiddleware
    from apps.demo_target.security.blocklist import get_blocked_ips, clear_blocklist
    from apps.demo_target.security.sessions import get_disabled_sessions, clear_disabled_sessions
    from apps.demo_target.telemetry.emitter import (
        emit_auth_failure,
        emit_auth_success,
        emit_http_request,
        emit_suspicious_request,
        emit_resource_access,
        emit_privilege_change,
        flush_telemetry
    )
except ImportError:
    from security.middleware import SecurityEnforcementMiddleware
    from security.blocklist import get_blocked_ips, clear_blocklist
    from security.sessions import get_disabled_sessions, clear_disabled_sessions
    from telemetry.emitter import (
        emit_auth_failure,
        emit_auth_success,
        emit_http_request,
        emit_suspicious_request,
        emit_resource_access,
        emit_privilege_change,
        flush_telemetry
    )


# Probe detection regexes (harmless evaluation without executing payload)
SQLI_PATTERN = re.compile(r"('|\bunion\b|\bselect\b|--|;\s*drop\b|\bor\b\s+['\d]|\bwhere\b)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script|javascript:|onerror=|<img|<svg|\balert\()", re.IGNORECASE)
TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini|boot\.ini)", re.IGNORECASE)


def get_client_ip(request: Request) -> str:
    """Extracts client IP, honoring X-Forwarded-For or X-Client-IP for simulated/proxied traffic."""
    xff = request.headers.get("X-Forwarded-For") or request.headers.get("X-Client-IP")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def get_session_info(request: Request):
    """Extracts user identity and session ID from headers."""
    auth = request.headers.get("Authorization") or ""
    sid = request.headers.get("X-Session-ID") or ""
    if not sid and auth.startswith("Bearer "):
        sid = auth[7:].strip()
    elif not sid and auth.startswith("Session "):
        sid = auth[8:].strip()

    user = None
    if sid:
        if "admin" in sid:
            user = "admin"
        elif "analyst" in sid:
            user = "analyst"
        elif "compromised" in sid:
            user = "admin_compromised"
        else:
            user = "user_standard"
    return user, sid


class LoginRequest(BaseModel):
    username: str
    password: str


class PrivilegeChangeRequest(BaseModel):
    targetUser: str
    newRole: str


def create_demo_target_app() -> FastAPI:
    app = FastAPI(
        title="GASHA Monitored Demo Target",
        description="Controlled enterprise web service demonstrating real-time defensive telemetry and active response.",
        version="0.1.0"
    )

    # Mount security enforcement middleware
    app.add_middleware(SecurityEnforcementMiddleware)

    @app.get("/health", tags=["System"])
    async def health_check():
        return {"status": "ok", "service": "gasha-demo-target", "version": "0.1.0"}

    @app.post("/api/auth/login", tags=["Authentication"])
    async def login(req: LoginRequest, request: Request):
        source_ip = get_client_ip(request)

        # Valid synthetic demo accounts
        if req.username == "admin" and req.password == "SuperAdmin2026!":
            session_id = f"sess-admin-{uuid.uuid4().hex[:8]}"
            emit_auth_success(source_ip, user_id="admin", session_id=session_id)
            return {"status": "success", "token": session_id, "user": "admin", "role": "admin"}

        if req.username == "analyst" and req.password == "AnalystPass2026!":
            session_id = f"sess-analyst-{uuid.uuid4().hex[:8]}"
            emit_auth_success(source_ip, user_id="analyst", session_id=session_id)
            return {"status": "success", "token": session_id, "user": "analyst", "role": "analyst"}

        # Authentication Failure
        emit_auth_failure(source_ip, user_id=req.username, reason="BAD_CREDENTIALS")
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"error": "INVALID_CREDENTIALS", "message": "Invalid username or password"}
        )

    @app.get("/api/tickets", tags=["Operations"])
    async def list_tickets(request: Request):
        source_ip = get_client_ip(request)
        user, sid = get_session_info(request)
        emit_resource_access(source_ip, user_id=user or "anonymous", resource_id="tickets", outcome="ALLOWED")
        return {
            "status": "success",
            "tickets": [
                {"id": "t-101", "title": "Database replication lag alert", "priority": "high"},
                {"id": "t-102", "title": "Customer portal onboarding", "priority": "medium"}
            ]
        }

    @app.get("/api/customers/lookup", tags=["Operations"])
    async def lookup_customers(request: Request, query: Optional[str] = Query(None)):
        source_ip = get_client_ip(request)
        user, sid = get_session_info(request)

        raw_query = query or ""
        # Check for harmless synthetic probe patterns
        matched_pattern = None
        if SQLI_PATTERN.search(raw_query):
            matched_pattern = "SQL_INJECTION"
        elif XSS_PATTERN.search(raw_query):
            matched_pattern = "XSS_PROBE"
        elif TRAVERSAL_PATTERN.search(raw_query):
            matched_pattern = "PATH_TRAVERSAL"

        if matched_pattern:
            # Emit telemetry recording the probe pattern
            emit_suspicious_request(
                source_ip=source_ip,
                path="/api/customers/lookup",
                pattern_type=matched_pattern,
                user_id=user,
                raw_query=raw_query
            )
            # Safe handled return without executing arbitrary SQL / script
            return {
                "status": "safe_handled",
                "detectedPattern": matched_pattern,
                "warning": f"Detected attack pattern [{matched_pattern}]. Payload neutralized.",
                "results": []
            }

        # Normal clean query
        emit_resource_access(source_ip, user_id=user or "anonymous", resource_id="customers", outcome="ALLOWED")
        return {
            "status": "success",
            "results": [
                {"id": "cust-501", "name": "Global Logistics Corp", "tier": "Enterprise"}
            ]
        }

    @app.get("/api/admin/dashboard", tags=["Administration"])
    async def admin_dashboard(request: Request):
        source_ip = get_client_ip(request)
        user, sid = get_session_info(request)

        if user != "admin":
            emit_http_request(source_ip, "GET", "/api/admin/dashboard", status_code=403, user_id=user)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "FORBIDDEN", "message": "Administrative privilege required."}
            )

        emit_resource_access(source_ip, user_id="admin", resource_id="admin_dashboard", outcome="ALLOWED")
        return {"status": "success", "clusterStatus": "healthy", "nodes": 12}

    @app.get("/api/admin/secrets", tags=["Administration"])
    async def admin_secrets(request: Request):
        source_ip = get_client_ip(request)
        user, sid = get_session_info(request)

        if user != "admin":
            emit_http_request(source_ip, "GET", "/api/admin/secrets", status_code=403, user_id=user)
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "FORBIDDEN", "message": "Access denied to crown jewel secrets."}
            )

        emit_resource_access(source_ip, user_id="admin", resource_id="crown_jewel_secrets", outcome="ALLOWED")
        return {"status": "success", "crownJewel": "CROWN_JEWEL_ENCRYPTED_DATABASE_KEY_2026"}

    @app.post("/api/admin/privilege-change", tags=["Administration"])
    async def privilege_change(req: PrivilegeChangeRequest, request: Request):
        source_ip = get_client_ip(request)
        user, sid = get_session_info(request)

        # Requires admin session to mutate roles
        if user != "admin":
            emit_privilege_change(
                source_ip=source_ip,
                user_id=req.targetUser,
                old_role="viewer",
                new_role=req.newRole,
                outcome="DENIED"
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": "UNAUTHORIZED_ROLE_MUTATION", "message": "Privilege mutation denied."}
            )

        emit_privilege_change(
            source_ip=source_ip,
            user_id=req.targetUser,
            old_role="viewer",
            new_role=req.newRole,
            outcome="UPDATED"
        )
        return {"status": "success", "message": f"User {req.targetUser} role updated to {req.newRole}"}

    @app.get("/api/demo/security-state", tags=["Observability"])
    async def get_security_state():
        """Observability endpoint returning current containment state."""
        return {
            "blockedIps": sorted(list(get_blocked_ips())),
            "disabledSessions": sorted(list(get_disabled_sessions()))
        }

    @app.post("/api/demo/reset", tags=["Observability"])
    async def reset_demo_state():
        """Resets blocklists and disabled sessions for test isolation."""
        clear_blocklist()
        clear_disabled_sessions()
        flush_telemetry()
        return {"status": "reset_complete"}

    return app


app = create_demo_target_app()

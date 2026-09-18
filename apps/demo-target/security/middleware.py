"""
==============================================================================
FILE: apps/demo-target/security/middleware.py
ROLE / OWNERSHIP: Full Team (Demo Target Defenses)
OBJECTIVE: Security enforcement middleware intercepting inbound HTTP requests on target app.
TOOLS & LIBRARIES: FastAPI / Starlette middleware
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - SecurityEnforcementMiddleware:
      1. Inspects client IP against blocklist (rejects with 403).
      2. Inspects session token against invalidated sessions list (rejects with 401).
EXPECTED RESULTS / BEHAVIOR:
  - Validates active defense response actions during live competition demonstrations.
==============================================================================
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from apps.demo_target.security.blocklist import is_blocked
from apps.demo_target.security.sessions import is_session_disabled

class SecurityEnforcementMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        if is_blocked(client_ip):
            return JSONResponse({"error": "ACCESS_BLOCKED_BY_GASHA", "message": "Source IP is blocked."}, status_code=403)
        return await call_next(request)

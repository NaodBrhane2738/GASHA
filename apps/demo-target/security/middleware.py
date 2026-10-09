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

try:
    from apps.demo_target.security.blocklist import is_blocked
    from apps.demo_target.security.sessions import is_session_disabled
except ImportError:
    from .blocklist import is_blocked
    from .sessions import is_session_disabled

class SecurityEnforcementMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, trusted_proxies=None):
        super().__init__(app)
        self.trusted_proxies = set(trusted_proxies if trusted_proxies is not None else ["127.0.0.1", "::1", "testclient"])

    def _resolve_client_ip(self, request) -> str:
        peer_ip = request.client.host if (request.client and request.client.host) else "127.0.0.1"

        # Direct peer is not in trusted_proxies: ignore all forwarded headers
        if peer_ip not in self.trusted_proxies:
            return peer_ip

        # Direct peer is trusted: inspect X-Forwarded-For from right to left
        xff = request.headers.get("X-Forwarded-For")
        if not xff:
            return request.headers.get("X-Real-IP") or peer_ip

        # Parse hops safely (protect against excessive length)
        raw_hops = [h.strip() for h in xff.split(",") if h.strip()]
        if not raw_hops or len(raw_hops) > 30:
            return peer_ip

        # Walk right-to-left: skip trusted proxies until the first untrusted IP
        for hop in reversed(raw_hops):
            if hop not in self.trusted_proxies:
                return hop

        return raw_hops[0]

    async def dispatch(self, request, call_next):
        # 1. Authoritative client IP resolution with trusted proxy verification
        peer_ip = request.client.host if (request.client and request.client.host) else "127.0.0.1"

        # Direct connecting peer cannot bypass active blocklist
        if is_blocked(peer_ip):
            return JSONResponse(
                {"error": "ACCESS_BLOCKED_BY_GASHA", "message": f"Source IP '{peer_ip}' is blocked by security policy."},
                status_code=403
            )

        client_ip = self._resolve_client_ip(request)
        if is_blocked(client_ip):
            return JSONResponse(
                {"error": "ACCESS_BLOCKED_BY_GASHA", "message": f"Source IP '{client_ip}' is blocked by security policy."},
                status_code=403
            )

        # 2. Inspect session token against invalidated sessions
        auth_header = request.headers.get("Authorization") or ""
        session_id = request.headers.get("X-Session-ID") or ""
        if not session_id and auth_header.startswith("Bearer "):
            session_id = auth_header[7:].strip()
        elif not session_id and auth_header.startswith("Session "):
            session_id = auth_header[8:].strip()

        if session_id and is_session_disabled(session_id):
            return JSONResponse(
                {"error": "SESSION_REVOKED_BY_GASHA", "message": f"Session '{session_id}' has been invalidated."},
                status_code=401
            )

        return await call_next(request)


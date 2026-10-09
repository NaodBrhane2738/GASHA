"""
GASHA ASGI / FastAPI Telemetry Middleware
Automatically captures and normalizes HTTP transactions, detects suspicious intrusion patterns,
measures latency, enforces trusted-proxy IP attribution, and transmits telemetry asynchronously.
"""
import time
import re
import uuid
import ipaddress
from typing import Optional, List, Callable, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

try:
    from .models import TelemetryEvent, TelemetryEventType, TelemetryEventPayload
    from .client import TelemetryClient
    from .sanitizers import sanitize_metadata
except (ImportError, ValueError):
    from models import TelemetryEvent, TelemetryEventType, TelemetryEventPayload
    from client import TelemetryClient
    from sanitizers import sanitize_metadata

# Pre-compiled passive intrusion pattern matchers
SQLI_PATTERN = re.compile(
    r"(\bunion\b.*\bselect\b|'|\"|\b(select|insert|update|delete|drop|alter)\b.*--|--|\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)",
    re.IGNORECASE
)
XSS_PATTERN = re.compile(
    r"(<script\b|javascript:|onerror=|onload=|eval\(|alert\(|<svg|<iframe)",
    re.IGNORECASE
)
TRAVERSAL_PATTERN = re.compile(
    r"(\.\./|\.\.\\|/etc/(passwd|shadow)|c:\\windows)",
    re.IGNORECASE
)

# Sensitive query parameter names whose values must be redacted from captured paths
SENSITIVE_PARAM_NAMES = {"password", "token", "secret", "key", "api_key", "apikey", "session", "auth"}

def sanitize_query_string(query_string: str) -> str:
    """Redacts values of sensitive query parameters in captured URL query strings."""
    if not query_string:
        return ""
    pairs = query_string.split("&")
    clean_pairs = []
    for pair in pairs:
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.lower() in SENSITIVE_PARAM_NAMES or any(s in k.lower() for s in ("pass", "secret", "token")):
                clean_pairs.append(f"{k}=[REDACTED]")
            else:
                clean_pairs.append(pair)
        else:
            clean_pairs.append(pair)
    return "&".join(clean_pairs)

class GashaTelemetryMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        client: Optional[TelemetryClient] = None,
        trusted_proxies: Optional[List[str]] = None,
        ignore_prefixes: Optional[List[str]] = None,
        suppress_paths: Optional[List[str]] = None,
        service_name: Optional[str] = None
    ):
        super().__init__(app)
        self.client = client or TelemetryClient(auto_start=False)
        self.service_name = service_name or self.client.service_name
        self.trusted_proxies: Set[str] = set(trusted_proxies if trusted_proxies is not None else ["127.0.0.1", "::1"])
        self.ignore_prefixes = suppress_paths or ignore_prefixes or [
            "/api/v1/telemetry/ingest",
            "/health",
            "/healthz",
            "/static",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico"
        ]

    def _is_trusted_proxy(self, ip_str: str) -> bool:
        """Determines if the connecting peer IP is a recognized trusted proxy."""
        clean_ip = ip_str.strip()
        if clean_ip in self.trusted_proxies:
            return True
        for trusted in self.trusted_proxies:
            try:
                if "/" in trusted and ipaddress.ip_address(clean_ip) in ipaddress.ip_network(trusted, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _resolve_client_ip(self, request: Request) -> tuple[str, str]:
        """
        Resolves authoritative client IP vs observed peer IP.
        Only parses X-Forwarded-For if connecting peer is in trusted_proxies.
        Returns: (authoritative_client_ip, observed_peer_ip)
        """
        peer_ip = request.client.host if (request.client and request.client.host) else "127.0.0.1"
        
        # If the connecting direct peer is NOT a trusted proxy, ignore forwarded headers
        if not self._is_trusted_proxy(peer_ip):
            return peer_ip, peer_ip

        # Direct peer is trusted: safely inspect forwarded headers from right to left
        forwarded_for = request.headers.get("x-forwarded-for")
        real_ip = request.headers.get("x-real-ip")

        if forwarded_for:
            raw_hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
            if raw_hops and len(raw_hops) <= 30:
                # Walk right-to-left: skip trusted proxies until the first untrusted IP
                for hop in reversed(raw_hops):
                    if not self._is_trusted_proxy(hop):
                        return hop, peer_ip
                return raw_hops[0], peer_ip
            return peer_ip, peer_ip
        elif real_ip:
            clean_real = real_ip.strip()
            return clean_real, peer_ip

        return peer_ip, peer_ip

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Suppress recursive telemetry or static path monitoring
        if any(path.startswith(prefix) for prefix in self.ignore_prefixes):
            return await call_next(request)

        start_time = time.time()
        client_ip, peer_ip = self._resolve_client_ip(request)
        correlation_id = request.headers.get("x-correlation-id") or f"corr-{uuid.uuid4().hex[:8]}"
        user_agent = request.headers.get("user-agent")
        method = request.method

        raw_query = request.url.query
        clean_query = sanitize_query_string(raw_query)
        clean_path = f"{path}?{clean_query}" if clean_query else path

        # Passive inspection of query and path for suspicious patterns
        suspicious_tags = []
        if SQLI_PATTERN.search(raw_query) or SQLI_PATTERN.search(path):
            suspicious_tags.append("SQL_INJECTION_PROBE")
        if XSS_PATTERN.search(raw_query) or XSS_PATTERN.search(path):
            suspicious_tags.append("CROSS_SITE_SCRIPTING_PROBE")
        if TRAVERSAL_PATTERN.search(path) or TRAVERSAL_PATTERN.search(raw_query):
            suspicious_tags.append("PATH_TRAVERSAL_PROBE")

        # Process the HTTP request; NEVER block or alter normal application behavior here
        status_code = 500
        error_msg = None
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception as exc:
            error_msg = str(exc)
            raise exc
        finally:
            latency_ms = round((time.time() - start_time) * 1000, 2)

            # If passive attack pattern was detected, emit dedicated SUSPICIOUS_REQUEST security event
            if suspicious_tags:
                try:
                    probe_event = TelemetryEvent(
                        id=f"telem-{uuid.uuid4().hex[:12]}",
                        eventType=TelemetryEventType.SUSPICIOUS_REQUEST,
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        sourceService=self.service_name,
                        environmentId=self.client.environment_id,
                        payload=TelemetryEventPayload(
                            sourceIp=client_ip,
                            observedPeerIp=peer_ip,
                            httpMethod=method,
                            httpPath=clean_path,
                            action="INTRUSION_PROBE",
                            outcome="DETECTED_PASSIVE",
                            metadata=sanitize_metadata({
                                "pattern_type": suspicious_tags[0],
                                "suspicious_tags": suspicious_tags,
                                "route": path
                            })
                        )
                    )
                    self.client.enqueue(probe_event)
                except Exception:
                    pass

            # Determine HTTP transaction classification
            if status_code == 401 or status_code == 403:
                event_type = TelemetryEventType.AUTH_FAILURE if "/auth" in path or "/login" in path else TelemetryEventType.HTTP_REQUEST
                action = "ACCESS_DENIED"
                outcome = "DENIED"
            elif status_code >= 500 or error_msg:
                event_type = TelemetryEventType.HTTP_REQUEST
                action = "SERVER_ERROR"
                outcome = "ERROR"
            else:
                event_type = TelemetryEventType.HTTP_REQUEST
                action = "HTTP_TRANSACTION"
                outcome = "SUCCESS"

            meta = {
                "route": path,
                "query": clean_query,
                "error": error_msg,
            }
            # Strip None values
            meta = {k: v for k, v in meta.items() if v is not None}

            payload = TelemetryEventPayload(
                sourceIp=client_ip,
                observedPeerIp=peer_ip,
                userAgent=user_agent,
                userId=request.state.user_id if hasattr(request.state, "user_id") else None,
                sessionId=request.state.session_id if hasattr(request.state, "session_id") else None,
                httpMethod=method,
                httpPath=clean_path,
                httpStatusCode=status_code,
                resourceAccessed=path,
                action=action,
                outcome=outcome,
                latencyMs=latency_ms,
                correlationId=correlation_id,
                metadata=sanitize_metadata(meta)
            )

            event = TelemetryEvent(
                id=f"telem-{uuid.uuid4().hex[:12]}",
                eventType=event_type,
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                sourceService=self.service_name,
                environmentId=self.client.environment_id,
                payload=payload
            )

            # Enqueue asynchronously; failures must NEVER disrupt the host application
            try:
                self.client.enqueue(event)
            except Exception:
                pass

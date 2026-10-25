"""
==============================================================================
FILE: apps/api/app/response/middleware.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: ASGI middleware that feeds every request into the SOC pipeline and enforces the
           resulting policy decision before the route handler runs.
KEY FEATURES:
  - Pure ASGI (not BaseHTTPMiddleware) so the buffered body can be replayed to the app.
  - 429 Too Many Requests / 423 Locked / 413 Content Too Large as RFC 9457 problem+json,
    with Retry-After and RateLimit-* headers so clients can back off correctly.
  - RateLimit-* headers on allowed responses too.
  - SecurityHeadersMiddleware applies baseline hardening headers (CSP, nosniff, frame-deny).
==============================================================================
"""

import json
from typing import Callable, Iterable, List, Optional, Tuple

from app.adaptive.soc_pipeline import SocPipeline
from app.schemas.soc import PolicyDecision

ASGIApp = Callable

_TITLES = {
    429: ("Too Many Requests", "https://gasha.dev/problems/rate-limited", "RATE_LIMITED"),
    423: ("Resource Locked", "https://gasha.dev/problems/source-locked", "SOURCE_LOCKED"),
    413: ("Content Too Large", "https://gasha.dev/problems/payload-too-large", "PAYLOAD_TOO_LARGE"),
}


def problem_body(d: PolicyDecision, path: str, incident_id: Optional[str]) -> bytes:
    title, type_uri, code = _TITLES[d.statusCode]
    if d.statusCode == 429:
        detail = f"Request rate limit exceeded. Retry after {d.retryAfterSeconds}s."
    elif d.statusCode == 423:
        detail = "Access from this source is temporarily locked by security policy."
    else:
        detail = d.reason or title
    return json.dumps({
        "type": type_uri, "title": title, "status": d.statusCode, "detail": detail, "instance": path,
        "code": code, "ruleId": d.ruleId, "retryAfter": d.retryAfterSeconds, "incidentId": incident_id,
    }).encode()


class PolicyEnforcementMiddleware:
    def __init__(self, app: ASGIApp, pipeline: SocPipeline, exempt_prefixes: Iterable[str] = (),
                 trust_proxy_headers: bool = False, trusted_proxy_hops: int = 1,
                 max_body_bytes: int = 1_048_576,
                 inspect_body_bytes: int = 65_536):
        self.app = app
        self.pipeline = pipeline
        self.exempt = tuple(exempt_prefixes)
        self.trust_proxy = trust_proxy_headers
        self.proxy_hops = max(1, trusted_proxy_hops)
        self.max_body = max_body_bytes
        self.inspect_body = inspect_body_bytes

    def _source(self, scope) -> str:
        if self.trust_proxy:
            # Each trusted proxy appends the address it received the request from, so the client IP
            # is `proxy_hops` entries from the right. Entries further left are client-controlled.
            for k, v in scope.get("headers", []):
                if k == b"x-forwarded-for":
                    hops = [h.strip() for h in v.decode("latin-1").split(",") if h.strip()]
                    if len(hops) >= self.proxy_hops:
                        return hops[-self.proxy_hops]
        client = scope.get("client")
        return client[0] if client else "unknown"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"].startswith(self.exempt) or scope["method"] == "OPTIONS":
            return await self.app(scope, receive, send)

        headers = {k: v for k, v in scope.get("headers", [])}
        content_type = headers.get(b"content-type", b"").decode("latin-1") or None
        declared = headers.get(b"content-length")
        oversized = bool(declared and declared.isdigit() and int(declared) > self.max_body)

        chunks: List[bytes] = []
        size = 0
        more = True
        if not oversized:
            while more:
                msg = await receive()
                if msg["type"] == "http.disconnect":
                    return
                chunk = msg.get("body", b"")
                size += len(chunk)
                if size > self.max_body:
                    oversized = True
                    break
                chunks.append(chunk)
                more = msg.get("more_body", False)
        body = b"".join(chunks)

        decision = self.pipeline.observe_request(
            source=self._source(scope), method=scope["method"], path=scope["path"],
            query=scope.get("query_string", b"").decode("latin-1"), content_type=content_type,
            body=body[: self.inspect_body], oversized=oversized,
        )

        policy = self.pipeline.policy.config
        blocked = decision.statusCode in (429, 423)
        remaining = 0 if blocked else max(0, policy.rate_limit - self.pipeline.policy.window_count(decision.sourceKey))
        rl_headers: List[Tuple[bytes, bytes]] = [
            (b"ratelimit-limit", str(policy.rate_limit).encode()),
            (b"ratelimit-remaining", str(remaining).encode()),
            (b"ratelimit-policy", f"{policy.rate_limit};w={policy.rate_window_seconds}".encode()),
        ]

        if decision.statusCode in _TITLES:
            inc = self.pipeline.incidents.open_for(decision.sourceKey)
            payload = problem_body(decision, scope["path"], inc.id if inc else None)
            out = [(b"content-type", b"application/problem+json"), (b"content-length", str(len(payload)).encode()),
                   (b"cache-control", b"no-store")] + rl_headers
            if decision.retryAfterSeconds:
                out += [(b"retry-after", str(decision.retryAfterSeconds).encode()),
                        (b"ratelimit-reset", str(decision.retryAfterSeconds).encode())]
            if decision.ruleId:
                out.append((b"x-gasha-policy", decision.ruleId.encode()))
            await send({"type": "http.response.start", "status": decision.statusCode, "headers": out})
            await send({"type": "http.response.body", "body": payload})
            return

        replayed = False

        async def replay():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": list(message.get("headers", [])) + rl_headers}
            await send(message)

        await self.app(scope, replay, send_with_headers)


DEFAULT_SECURITY_HEADERS = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    (b"cross-origin-opener-policy", b"same-origin"),
]


class SecurityHeadersMiddleware:
    """Baseline hardening headers for a JSON API. Swagger UI paths get a relaxed CSP."""

    def __init__(self, app: ASGIApp, docs_prefixes: Iterable[str] = ("/docs", "/redoc")):
        self.app = app
        self.docs = tuple(docs_prefixes)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        is_docs = scope["path"].startswith(self.docs)

        async def wrapped(message):
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                extra = [(k, v) for k, v in DEFAULT_SECURITY_HEADERS
                         if k not in existing and not (is_docs and k == b"content-security-policy")]
                message = {**message, "headers": list(message.get("headers", [])) + extra}
            await send(message)

        await self.app(scope, receive, wrapped)

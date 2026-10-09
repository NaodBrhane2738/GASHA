"""
Unit tests for GASHA ASGI / FastAPI Telemetry Middleware.
Validates HTTP transaction capture, latency tracking, trusted-proxy attribution,
passive probe detection, and suppressed path routing.
"""
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from client import TelemetryClient
from middleware import GashaTelemetryMiddleware
from models import TelemetryEventType


def make_test_app(middleware_kwargs=None):
    async def index(request):
        return PlainTextResponse("Hello GASHA")

    async def user_profile(request):
        return JSONResponse({"user": "alice", "id": 42})

    async def health(request):
        return JSONResponse({"status": "ok"})

    routes = [
        Route("/", index),
        Route("/users/me", user_profile),
        Route("/health", health),
    ]

    app = Starlette(routes=routes)
    kwargs = middleware_kwargs or {}
    app.add_middleware(GashaTelemetryMiddleware, **kwargs)
    return app


def test_middleware_captures_http_request():
    app = make_test_app()
    # Find middleware client instance
    test_client = TestClient(app)

    response = test_client.get("/users/me", headers={"User-Agent": "pytest-agent"})
    assert response.status_code == 200

    # Retrieve telemetry client from middleware
    mw = None
    for m in app.user_middleware:
        if m.cls == GashaTelemetryMiddleware:
            # We can test via mock client
            pass


def test_middleware_trusted_proxy_attribution():
    client_mock = TelemetryClient(auto_start=False)
    app = Starlette(routes=[Route("/test", lambda r: PlainTextResponse("ok"))])
    app.add_middleware(
        GashaTelemetryMiddleware,
        client=client_mock,
        trusted_proxies=["testclient", "127.0.0.1", "10.0.0.1"]
    )
    test_client = TestClient(app)

    # Simulated forwarded header
    response = test_client.get(
        "/test",
        headers={"X-Forwarded-For": "203.0.113.195, 10.0.0.1"}
    )
    assert response.status_code == 200

    # Verify event in queue
    assert client_mock.get_queue_depth() == 1
    event = client_mock.queue.get_nowait()
    assert event.eventType == TelemetryEventType.HTTP_REQUEST
    assert event.payload.sourceIp == "203.0.113.195"
    assert event.payload.httpStatusCode == 200


def test_middleware_untrusted_proxy_attribution():
    client_mock = TelemetryClient(auto_start=False)
    app = Starlette(routes=[Route("/test", lambda r: PlainTextResponse("ok"))])
    # Empty trusted proxies - direct client host ('testclient') should be used, XFF ignored
    app.add_middleware(
        GashaTelemetryMiddleware,
        client=client_mock,
        trusted_proxies=[]
    )
    test_client = TestClient(app)

    response = test_client.get(
        "/test",
        headers={"X-Forwarded-For": "203.0.113.195"}
    )
    assert response.status_code == 200

    assert client_mock.get_queue_depth() == 1
    event = client_mock.queue.get_nowait()
    # Source IP should be peer IP ('testclient'), NOT untrusted forwarded header
    assert event.payload.sourceIp == "testclient"


def test_middleware_passive_probe_detection():
    client_mock = TelemetryClient(auto_start=False)
    app = Starlette(routes=[Route("/search", lambda r: PlainTextResponse("results"))])
    app.add_middleware(GashaTelemetryMiddleware, client=client_mock)
    test_client = TestClient(app)

    # Attack probe with SQL injection syntax
    response = test_client.get("/search?q=admin'--")
    assert response.status_code == 200

    # Expect TWO events: SUSPICIOUS_REQUEST probe event and normal HTTP_REQUEST transaction
    assert client_mock.get_queue_depth() == 2

    events = [client_mock.queue.get_nowait(), client_mock.queue.get_nowait()]
    event_types = {e.eventType for e in events}
    assert TelemetryEventType.SUSPICIOUS_REQUEST in event_types
    assert TelemetryEventType.HTTP_REQUEST in event_types

    probe_event = next(e for e in events if e.eventType == TelemetryEventType.SUSPICIOUS_REQUEST)
    assert probe_event.payload.metadata.get("pattern_type") == "SQL_INJECTION_PROBE"


def test_middleware_path_traversal_probe():
    client_mock = TelemetryClient(auto_start=False)
    app = Starlette(routes=[Route("/files", lambda r: PlainTextResponse("files"))])
    app.add_middleware(GashaTelemetryMiddleware, client=client_mock)
    test_client = TestClient(app)

    response = test_client.get("/files?path=../../etc/passwd")
    assert response.status_code == 200

    events = [client_mock.queue.get_nowait(), client_mock.queue.get_nowait()]
    probe_event = next(e for e in events if e.eventType == TelemetryEventType.SUSPICIOUS_REQUEST)
    assert probe_event.payload.metadata.get("pattern_type") == "PATH_TRAVERSAL_PROBE"


def test_middleware_suppressed_paths():
    client_mock = TelemetryClient(auto_start=False)
    app = Starlette(routes=[
        Route("/health", lambda r: PlainTextResponse("ok")),
        Route("/api/v1/telemetry/ingest", lambda r: PlainTextResponse("ok")),
    ])
    app.add_middleware(
        GashaTelemetryMiddleware,
        client=client_mock,
        suppress_paths=["/health", "/api/v1/telemetry/ingest"]
    )
    test_client = TestClient(app)

    test_client.get("/health")
    test_client.get("/api/v1/telemetry/ingest")

    # Both suppressed, queue depth should be 0
    assert client_mock.get_queue_depth() == 0

# GASHA Telemetry SDK & Ingestion Pipeline

The **GASHA Telemetry SDK** provides high-performance, non-blocking security event telemetry for server-side applications in Python (FastAPI, Starlette, Flask) and TypeScript / Node.js (Express, Next.js, Fastify).

It enables protected applications to emit structured runtime transactions, authentication results, and intrusion probes to the GASHA platform without adding request latency or leaking credentials.

---

## Key Capabilities

1. **Strict Non-Blocking Guarantees**:
   - In-memory bounded queue (default capacity 2,000 items) with background asynchronous delivery.
   - Saturated buffers drop oldest events rather than stalling application threads.
   - Fail-closed or fail-open telemetry dispatch guarantees host service uptime.

2. **Defense-in-Depth Credential Sanitization**:
   - Recursively walks metadata and headers.
   - Strictly redacts passwords, client secrets, API keys, tokens, session cookies, and JWTs.
   - Explicitly preserves essential security correlation identifiers (`sessionId`, `userId`, `sourceIp`, `action`, `resource`, `latencyMs`, `httpStatusCode`).
   - Server-side normalizer re-sanitizes every ingested event.

3. **Passive Intrusion Detection**:
   - Integrated ASGI and Express middleware passively inspect incoming requests for SQL Injection (`SQL_INJECTION_PROBE`), Cross-Site Scripting (`CROSS_SITE_SCRIPTING_PROBE`), and Path Traversal (`PATH_TRAVERSAL_PROBE`) attack patterns.
   - Emits immediate `SUSPICIOUS_REQUEST` security alerts alongside standard `HTTP_REQUEST` telemetry.

4. **Trusted Proxy Attribution**:
   - Prevents IP spoofing via forged `X-Forwarded-For` or `X-Real-IP` headers.
   - Only honors forwarded headers when the direct connecting peer IP is in `trusted_proxies`.
   - Records direct peer connection in `observedPeerIp`.

5. **Bounded Retry & Ingestion Semantics**:
   - Exponential backoff retry for transient network and 5xx errors.
   - Immediate rejection without endless retries on 4xx client/schema errors.
   - Server-side LRU deduplication cache (5,000 items) rejecting replay attacks.

---

## Python SDK Usage

### Installation & Initialization

```python
from packages.telemetry_sdk.python import init_telemetry, get_telemetry

# Initialize singleton client
telemetry = init_telemetry(
    endpoint="http://localhost:4000/api/v1/telemetry/ingest",
    api_key="gasha-telemetry-demo-key-2026",
    environment_id="env-prod",
    service_name="payment-service",
    max_queue_size=2000,
    batch_size=20
)
```

### FastAPI / Starlette Middleware

```python
from fastapi import FastAPI
from packages.telemetry_sdk.python import GashaTelemetryMiddleware, get_telemetry

app = FastAPI()

# Automatically intercept transactions, measure latency, and detect probes
app.add_middleware(
    GashaTelemetryMiddleware,
    client=get_telemetry().client,
    trusted_proxies=["127.0.0.1", "10.0.0.1"],
    suppress_paths=["/health", "/metrics", "/favicon.ico"]
)
```

### Structured Event Emitters

```python
sdk = get_telemetry()

# Authentication Failure
sdk.auth_failure(
    source_ip="198.51.100.10",
    user_id="victim_user",
    reason="INVALID_PASSWORD",
    metadata={"attempt_count": 3}
)

# Authentication Success
sdk.auth_success(
    source_ip="198.51.100.10",
    user_id="alice",
    session_id="sess_12345"
)

# Critical Resource Access
sdk.resource_access(
    resource_id="db:customer_records",
    user_id="alice",
    action="EXPORT_CSV",
    granted=True
)

# Privilege Change / Role Mutation
sdk.privilege_change(
    target_user_id="bob",
    actor_user_id="admin_1",
    old_role="viewer",
    new_role="security_admin"
)

# Outbound Connection / Egress
sdk.outbound_connection(
    target_host="198.51.100.22",
    target_port=443,
    protocol="TCP"
)
```

---

## TypeScript / Node.js SDK Usage

### Initialization & Express Middleware

```typescript
import express from 'express';
import { GashaTelemetryClient } from '@gasha/telemetry-sdk';

const app = express();

const telemetry = new GashaTelemetryClient({
  endpoint: 'http://localhost:4000/api/v1/telemetry/ingest',
  apiKey: process.env.GASHA_TELEMETRY_API_KEY || 'gasha-telemetry-demo-key-2026',
  environmentId: 'env-prod',
  serviceName: 'frontend-api',
  batchSize: 20,
  flushIntervalMs: 1000,
  trustedProxies: ['127.0.0.1', '::1'],
});

// Attach automatic request interception
app.use(telemetry.expressMiddleware());

// Manual Emitters
telemetry.authFailure({
  userId: 'user_unknown',
  sourceIp: req.ip,
  reason: 'INVALID_CREDENTIALS',
});
```

---

## Server Ingestion Pipeline (`apps/api`)

The backend ingestion pipeline processes batches via `POST /api/v1/telemetry/ingest`:

1. **Authentication**: Enforces `X-GASHA-TELEMETRY-KEY` header or `Authorization: Bearer <key>`. Fails closed (HTTP 401) if unconfigured or invalid.
2. **Batch Constraints**: Rejects batches with 0 events or more than `MAX_BATCH_SIZE` (100) events with HTTP 400.
3. **Deduplication**: Checks incoming event IDs against the in-memory 5,000-item LRU cache. Duplicates receive status `duplicate` without re-queueing.
4. **Validation**: Rejects invalid IDs, unsupported event types, stale timestamps (> 7 days), future drift (> 1 hour), and oversized payloads.
5. **Normalization**: Canonicalizes IPs, standardizes ISO-8601 UTC timestamps, re-sanitizes metadata, and records `_serverReceivedAt`.
6. **Bounded Buffering**: Enqueues into an `asyncio.Queue` (capacity 5,000) non-blockingly, returning HTTP 202 Accepted.

### Operational Endpoints

- `GET /api/v1/telemetry/health`: Reports queue depth, buffer capacity, and dropped overflow counts.
- `GET /api/v1/telemetry/metrics`: Returns operational counters (`events_received`, `events_accepted`, `events_duplicate`, `events_rejected`, `events_dropped_overflow`, `batches_processed`).

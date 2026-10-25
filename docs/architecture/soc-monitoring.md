# SOC Monitoring & Policy Enforcement

Real-time request inspection, defensive policy enforcement, incident lifecycle tracking,
alerting and remediation guidance. Everything is deterministic (no LLM in the decision path).

## Flow

```
request ──► PolicyEnforcementMiddleware ─┐
                                          ├─► SocPipeline ──► EventBus ──► audit log (gasha.soc.audit)
telemetry ──► POST /telemetry/ingest ────┘     │                    ├────► AlertDispatcher ──► SMTP / Resend
                                               │                    └────► GET /soc/stream (SSE) ──► web /soc
                                               ├─ detection/inspectors.py   (payload signatures, malformed JSON)
                                               ├─ response/policy.py        (rate limit, escalation, locks)
                                               ├─ adaptive/incidents.py     (lifecycle per source)
                                               └─ telemetry/metrics.py      (1 s buckets, 10 min ring)
```

Lifecycle: **INGESTED → DETECTED → ENFORCED → MITIGATED → (RESOLVED)**. An incident is
resolved when its mitigation expires or an analyst releases it; flag-only incidents resolve
after 30 quiet minutes.

## Decisions

| Trigger | Action | HTTP |
| --- | --- | --- |
| Source exceeds `SOC_RATE_LIMIT_REQUESTS` per window | THROTTLE | 429 + `Retry-After`, `RateLimit-*` |
| `SOC_ESCALATION_COUNT` throttle episodes in escalation window | LOCK | 423 |
| Finding ≥ `SOC_LOCK_ON_SEVERITY` (SQLi, traversal) | LOCK | 423 |
| `SOC_AUTH_FAILURE_LIMIT` AUTH_FAILURE events (telemetry) | LOCK | 423 (returned in ingest `enforcement`) |
| Body over `SOC_MAX_BODY_BYTES` | REJECT | 413 |
| Lower-severity finding (XSS probe, malformed JSON) | FLAG | request allowed |

Rejections use RFC 9457 `application/problem+json` with `code`, `ruleId`, `retryAfter` and
`incidentId`. The web client routes any 429/423/413 into the global `PolicyBanner`.

## API (`/api/v1/soc`, bearer JWT required, exempt from enforcement)

`GET /metrics?window=` · `GET /incidents` · `GET /incidents/{id}` · `GET /findings` ·
`GET /findings/{id}/analysis` · `GET /mitigations` · `DELETE /mitigations/{source}` · `GET /stream` (SSE)

The dashboard reads the stream with `fetch()` so the token stays in the `Authorization` header.

## Scaling notes

State is in-process and sized for a single API worker. With multiple workers, move
`SlidingWindowCounter` and the mitigation table to Redis and swap `EventBus` for Redis pub/sub;
the interfaces are already isolated for that.

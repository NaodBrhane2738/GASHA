"""
==============================================================================
FILE: apps/api/app/adaptive/soc_pipeline.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Orchestrates the incident response lifecycle for every observed request or
           telemetry event:
               Event Ingestion -> Anomaly Detection -> Policy Enforcement -> Mitigation
           and publishes each transition on the event bus.
KEY FEATURES:
  - observe_request(): used by the enforcement middleware for in-process traffic.
  - observe_telemetry(): used by /telemetry/ingest for events emitted by defended apps.
  - tick(): 1 Hz housekeeping (mitigation expiry, quiet-incident resolution, metrics push).
EXPECTED RESULTS / BEHAVIOR:
  - Detection, policy, incidents and metrics stay independent; only this module knows the order.
  - Consumers (audit log, alert dispatcher, SSE stream) see a consistent event sequence.
==============================================================================
"""

import asyncio
import logging
import uuid
from collections import OrderedDict
from typing import List, Optional

from app.adaptive.incidents import IncidentTracker
from app.core.events import EventBus, utc_iso
from app.detection.inspectors import RawFinding, inspect_request, oversized_finding, scan_value
from app.response.policy import Evaluation, PolicyEngine
from app.schemas.soc import SEVERITY_RANK, Finding, MetricsSnapshot, Mitigation, PolicyDecision, RateLimitPolicyView, SourceRate
from app.schemas.telemetry import TelemetryEventSchema
from app.telemetry.metrics import MetricsStore

logger = logging.getLogger("gasha.soc.pipeline")
audit = logging.getLogger("gasha.soc.audit")

_TITLES = {
    "RULE-RATE-001": "Request rate limit exceeded",
    "RULE-RATE-002": "Sustained rate-limit abuse",
    "RULE-AUTH-001": "Brute-force authentication attempt",
}

CATEGORY_TITLES = {
    "MALFORMED_PAYLOAD": "Malformed request payload",
    "OVERSIZED_PAYLOAD": "Oversized request payload",
    "SQL_INJECTION": "SQL injection attempt",
    "PATH_TRAVERSAL": "Path traversal attempt",
    "XSS_PROBE": "Cross-site scripting probe",
}


class SocPipeline:
    def __init__(self, bus: EventBus, policy: PolicyEngine, incidents: IncidentTracker,
                 metrics: MetricsStore, max_findings: int = 1000, max_body_bytes: int = 1_048_576):
        self.bus = bus
        self.policy = policy
        self.incidents = incidents
        self.metrics = metrics
        self.max_body_bytes = max_body_bytes
        self._findings: "OrderedDict[str, Finding]" = OrderedDict()
        self._max_findings = max_findings
        self._task: Optional[asyncio.Task] = None
        bus.on("*", self._audit)

    # ------------------------------------------------------------------ event logger
    @staticmethod
    def _audit(event) -> None:
        if event.type != "metrics.tick":
            audit.info("%s %s", event.type, event.model_dump_json(include={"id", "data"}))

    # ------------------------------------------------------------------ findings
    def _store(self, f: Finding) -> None:
        self._findings[f.id] = f
        while len(self._findings) > self._max_findings:
            self._findings.popitem(last=False)

    def get_finding(self, fid: str) -> Optional[Finding]:
        return self._findings.get(fid)

    def list_findings(self, limit: int = 100, source: Optional[str] = None) -> List[Finding]:
        items = [f for f in reversed(self._findings.values()) if not source or f.sourceKey == source]
        return items[:limit]

    def _materialise(self, raw: List[RawFinding], source: str, method: Optional[str], path: Optional[str]) -> List[Finding]:
        out = []
        for r in raw:
            out.append(Finding(
                id=f"fnd-{uuid.uuid4().hex[:10]}", ts=utc_iso(), sourceKey=source, method=method, path=path,
                category=r.category, ruleId=r.rule_id, severity=r.severity, location=r.location,
                field=r.field, evidence=r.evidence, diagnostic=r.diagnostic,
            ))
        return out

    # ------------------------------------------------------------------ lifecycle
    def _apply(self, ev: Evaluation, findings: List[Finding], method: Optional[str], path: Optional[str],
               ingest_detail: str) -> PolicyDecision:
        d = ev.decision
        source = d.sourceKey

        for m in ev.expired:
            self._on_mitigation_ended(m, "mitigation.expired", "rate returned below limit")

        # Policy-only rules (rate limit / brute force) get a synthetic finding for the analysis panel.
        if ev.new_mitigation and not findings:
            cat = "BRUTE_FORCE_AUTH" if d.ruleId == "RULE-AUTH-001" else "RATE_LIMIT_EXCEEDED"
            findings = self._materialise([RawFinding(
                rule_id=d.ruleId, category=cat, severity=d.severity, location="telemetry" if cat == "BRUTE_FORCE_AUTH" else "path",
                diagnostic=d.reason or "", evidence=None,
            )], source, method, path)

        if findings or ev.new_mitigation:
            worst = max((f.severity for f in findings), key=SEVERITY_RANK.__getitem__, default=d.severity)
            title = _TITLES.get(d.ruleId or "") or CATEGORY_TITLES.get(findings[0].category, findings[0].category)
            inc = self.incidents.ensure(source, title, worst, ingest_detail)
            for f in findings:
                f.incidentId = inc.id
                self._store(f)
                self.incidents.record_detection(inc, f)
                self.bus.publish("finding.created", f.model_dump())
            if ev.new_mitigation:
                self.incidents.record_enforcement(inc, ev.new_mitigation)
                self.bus.publish("policy.enforced", {
                    "decision": d.model_dump(), "mitigation": ev.new_mitigation.model_dump(),
                    "incident": inc.model_dump(), "findings": [f.model_dump() for f in findings],
                })
                # The triggering request is itself rejected, so mitigation is in effect immediately.
                ev.new_mitigation.blockedRequests += 1
                self.incidents.record_block(inc)
            self.bus.publish("incident.updated", inc.model_dump())

        if ev.blocked_by:
            inc = self.incidents.open_for(source)
            if inc:
                first_block = inc.stage != "MITIGATED"
                self.incidents.record_block(inc)
                if first_block or inc.blockedRequests % 25 == 0:
                    self.bus.publish("incident.updated", inc.model_dump())
            self.bus.publish("request.blocked", {"sourceKey": source, "action": d.action, "statusCode": d.statusCode,
                                                 "path": path, "retryAfterSeconds": d.retryAfterSeconds})
        return d

    def _on_mitigation_ended(self, m: Mitigation, event_type: str, why: str) -> None:
        self.bus.publish(event_type, m.model_dump())
        inc = self.incidents.resolve(m.sourceKey, f"{m.action.lower()} {why}")
        if inc:
            self.bus.publish("incident.updated", inc.model_dump())

    # ------------------------------------------------------------------ entry points
    def observe_request(self, source: str, method: str, path: str, query: str, content_type: Optional[str],
                        body: bytes, oversized: bool = False) -> PolicyDecision:
        raw = [oversized_finding(self.max_body_bytes)] if oversized else inspect_request(path, query, content_type, body)
        findings = self._materialise(raw, source, method, path)
        ev = self.policy.evaluate_request(source, [f.model_dump() for f in findings])
        if oversized and ev.decision.action in ("ALLOW", "FLAG"):
            ev.decision = ev.decision.model_copy(update={"action": "REJECT", "statusCode": 413,
                                                         "reason": "Request body too large"})
        d = self._apply(ev, findings, method, path,
                        f"{method} {path} — {self.policy.window_count(source)} req in window")
        self.metrics.record(d.action, self.policy.window_count(source))
        return d

    def observe_telemetry(self, event: TelemetryEventSchema) -> Optional[PolicyDecision]:
        p = event.payload
        source = p.sourceIp or p.sessionId or event.sourceService
        detail = f"{event.eventType} from {event.sourceService}"

        if event.eventType == "AUTH_FAILURE":
            ev = self.policy.evaluate_auth_failure(source)
            if ev:
                return self._apply(ev, [], p.httpMethod, p.httpPath, detail)
            return None

        if event.eventType in ("HTTP_REQUEST", "SUSPICIOUS_REQUEST"):
            raw: List[RawFinding] = []
            if p.httpPath:
                path, _, query = p.httpPath.partition("?")
                raw = inspect_request(path, query, None, b"")
            for k, v in (p.metadata or {}).items():
                if isinstance(v, str):
                    raw.extend(scan_value(v, "telemetry", k))
            findings = self._materialise(raw, source, p.httpMethod, p.httpPath)
            ev = self.policy.evaluate_request(source, [f.model_dump() for f in findings])
            d = self._apply(ev, findings, p.httpMethod, p.httpPath, detail)
            self.metrics.record(d.action, self.policy.window_count(source))
            return d
        return None

    def release(self, source: str) -> Optional[Mitigation]:
        m = self.policy.release(source)
        if m:
            self._on_mitigation_ended(m, "mitigation.released", "released by analyst")
        return m

    # ------------------------------------------------------------------ housekeeping
    def tick(self) -> None:
        for m in self.policy.sweep():
            self._on_mitigation_ended(m, "mitigation.expired", "mitigation window elapsed")
        for inc in self.incidents.sweep_quiet():
            self.bus.publish("incident.updated", inc.model_dump())
        if self.bus.subscriber_count:
            self.bus.publish("metrics.tick", {
                "bucket": self.metrics.current().model_dump(),
                "activeMitigations": [m.model_dump() for m in self.policy.active_mitigations()],
                "stageCounts": self.incidents.counts(),
            })

    def snapshot(self, window_seconds: int = 300) -> MetricsSnapshot:
        cfg = self.policy.config
        return MetricsSnapshot(
            series=self.metrics.series(window_seconds),
            policy=RateLimitPolicyView(
                limit=cfg.rate_limit, windowSeconds=cfg.rate_window_seconds,
                escalationCount=cfg.escalation_count, escalationWindowSeconds=cfg.escalation_window_seconds,
                lockDurationSeconds=cfg.lock_duration_seconds,
            ),
            activeMitigations=self.policy.active_mitigations(),
            topSources=[SourceRate(sourceKey=k, requestsInWindow=n) for k, n in self.policy.requests.top(5)],
            totals=dict(self.metrics.totals) | {f"stage{k.title()}": v for k, v in self.incidents.counts().items()},
        )

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(1)
            try:
                self.tick()
            except Exception:
                logger.exception("SOC tick failed")

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="gasha-soc-tick")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

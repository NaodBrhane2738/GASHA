import asyncio

from app.adaptive.incidents import IncidentTracker
from app.adaptive.soc_pipeline import SocPipeline
from app.core.events import EventBus
from app.detection.inspectors import inspect_request
from app.detection.rate_window import SlidingWindowCounter
from app.notifications.dispatcher import AlertDispatcher
from app.response.policy import PolicyConfig, PolicyEngine
from app.telemetry.metrics import MetricsStore


class FakeClock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def make_pipeline(clock=None, **cfg):
    clock = clock or FakeClock()
    bus = EventBus()
    policy = PolicyEngine(PolicyConfig(**cfg), clock=clock)
    return bus, SocPipeline(bus, policy, IncidentTracker(), MetricsStore())


# ---------------------------------------------------------------- detection

def test_sliding_window_counts_and_retry_after():
    clock = FakeClock()
    w = SlidingWindowCounter(10, clock)
    for _ in range(3):
        w.hit("a")
    assert w.count("a") == 3
    assert w.seconds_until_below("a", 3) == 10
    clock.t += 10.5
    assert w.count("a") == 0


def test_inspector_flags_sqli_in_json_body_with_field_path():
    body = b'{"user": {"name": "x\' OR \'1\'=\'1"}}'
    findings = inspect_request("/login", "", "application/json", body)
    assert [f.category for f in findings] == ["SQL_INJECTION"]
    assert findings[0].field == "user.name"
    assert findings[0].location == "body"


def test_inspector_flags_traversal_in_encoded_query():
    findings = inspect_request("/files", "name=..%2F..%2Fetc%2Fpasswd", None, b"")
    assert findings[0].category == "PATH_TRAVERSAL"
    assert findings[0].field == "name"


def test_inspector_reports_malformed_json_position():
    findings = inspect_request("/api", "", "application/json", b'{"a": 1,,}')
    assert findings[0].category == "MALFORMED_PAYLOAD"
    assert "column" in findings[0].diagnostic


def test_benign_request_has_no_findings():
    assert inspect_request("/api/v1/assets", "page=2&q=web server", "application/json", b'{"name": "O\'Brien"}') == []


def test_evidence_is_truncated_and_printable():
    payload = "<script>" + "A" * 500 + "\x00"
    f = inspect_request("/", f"q={payload}", None, b"")[0]
    assert len(f.evidence) <= 120 and "\x00" not in f.evidence


# ---------------------------------------------------------------- policy

def test_rate_limit_throttles_then_escalates_to_lock():
    clock = FakeClock()
    policy = PolicyEngine(PolicyConfig(rate_limit=3, rate_window_seconds=10, escalation_count=2), clock=clock)
    actions = [policy.evaluate_request("1.2.3.4").decision.action for _ in range(4)]
    assert actions == ["ALLOW", "ALLOW", "ALLOW", "THROTTLE"]
    d = policy.evaluate_request("1.2.3.4").decision
    assert d.statusCode == 429 and d.retryAfterSeconds and d.retryAfterSeconds <= 10

    clock.t += 11  # window drains, throttle lifts
    assert policy.evaluate_request("1.2.3.4").decision.action == "ALLOW"
    for _ in range(3):
        policy.evaluate_request("1.2.3.4")
    d = policy.evaluate_request("1.2.3.4").decision  # second throttle episode -> lock
    assert d.action == "LOCK" and d.statusCode == 423 and d.ruleId == "RULE-RATE-002"


def test_high_severity_finding_locks_source_and_lock_persists():
    policy = PolicyEngine(PolicyConfig(), clock=FakeClock())
    ev = policy.evaluate_request("5.5.5.5", [{"id": "f1", "severity": "CRITICAL", "ruleId": "RULE-INJ-002",
                                             "category": "SQL_INJECTION"}])
    assert ev.decision.statusCode == 423 and ev.new_mitigation
    follow = policy.evaluate_request("5.5.5.5")
    assert follow.decision.statusCode == 423 and follow.blocked_by
    assert policy.mitigation_for("5.5.5.5").blockedRequests == 1


def test_medium_finding_is_flagged_not_blocked():
    policy = PolicyEngine(PolicyConfig(), clock=FakeClock())
    ev = policy.evaluate_request("6.6.6.6", [{"id": "f1", "severity": "MEDIUM", "ruleId": "RULE-XSS-001",
                                             "category": "XSS_PROBE"}])
    assert ev.decision.action == "FLAG" and ev.decision.statusCode == 200


def test_auth_failure_brute_force_locks():
    policy = PolicyEngine(PolicyConfig(auth_failure_limit=3), clock=FakeClock())
    assert policy.evaluate_auth_failure("7.7.7.7") is None
    assert policy.evaluate_auth_failure("7.7.7.7") is None
    ev = policy.evaluate_auth_failure("7.7.7.7")
    assert ev.decision.statusCode == 423 and ev.decision.ruleId == "RULE-AUTH-001"


# ---------------------------------------------------------------- pipeline + lifecycle

def test_pipeline_walks_full_lifecycle_and_publishes_events():
    clock = FakeClock()
    bus, pipe = make_pipeline(clock, lock_duration_seconds=30)
    seen = []
    bus.on("*", lambda e: seen.append(e.type))

    d = pipe.observe_request("9.9.9.9", "GET", "/search", "q=1 UNION SELECT password FROM users", None, b"")
    assert d.statusCode == 423
    inc = pipe.incidents.open_for("9.9.9.9")
    assert [s.stage for s in inc.steps] == ["INGESTED", "DETECTED", "ENFORCED", "MITIGATED"]
    assert inc.status == "MITIGATED" and inc.severity == "CRITICAL"
    assert {"finding.created", "policy.enforced", "incident.updated"} <= set(seen)
    assert pipe.incidents.counts() == {"INGESTED": 1, "DETECTED": 1, "ENFORCED": 1, "MITIGATED": 1, "RESOLVED": 0}

    pipe.observe_request("9.9.9.9", "GET", "/", "", None, b"")
    assert "request.blocked" in seen

    clock.t += 31
    pipe.tick()
    assert pipe.incidents.get(inc.id).status == "RESOLVED"
    assert "mitigation.expired" in seen


def test_pipeline_rate_limit_creates_synthetic_finding_with_analysis():
    from app.adaptive.remediation import analyze
    _, pipe = make_pipeline(rate_limit=2)
    for _ in range(3):
        d = pipe.observe_request("8.8.8.8", "GET", "/api/v1/assets", "", None, b"")
    assert d.statusCode == 429
    f = pipe.list_findings(source="8.8.8.8")[0]
    assert f.category == "RATE_LIMIT_EXCEEDED"
    a = analyze(f, [])
    assert any("429" in (r.snippet or "") for r in a.recommendations)


def test_release_resolves_incident():
    _, pipe = make_pipeline()
    pipe.observe_request("4.4.4.4", "GET", "/f", "p=../../etc/passwd", None, b"")
    assert pipe.release("4.4.4.4")
    assert pipe.incidents.open_for("4.4.4.4") is None
    assert pipe.observe_request("4.4.4.4", "GET", "/ok", "", None, b"").action == "ALLOW"


def test_metrics_record_decisions():
    _, pipe = make_pipeline(rate_limit=1)
    pipe.observe_request("3.3.3.3", "GET", "/", "", None, b"")
    pipe.observe_request("3.3.3.3", "GET", "/", "", None, b"")
    assert pipe.metrics.totals["allowed"] == 1 and pipe.metrics.totals["throttled"] == 1
    snap = pipe.snapshot(10)
    assert snap.series[-1].peakSourceRate == 2 and snap.policy.limit == 1


# ---------------------------------------------------------------- alerts

class RecordingTransport:
    name = "test"

    def __init__(self, fail_times=0):
        self.sent = []
        self.fail_times = fail_times

    async def send(self, alert):
        if self.fail_times:
            self.fail_times -= 1
            raise ConnectionError("smtp down")
        self.sent.append(alert)
        return "msg-1"


def test_alert_dispatcher_sends_once_per_cooldown_and_escapes_html():
    async def run():
        clock = FakeClock()
        bus, pipe = make_pipeline(clock)
        transport = RecordingTransport()
        alerts = AlertDispatcher(bus, transport, "soc@x", ["oncall@x"], cooldown_seconds=60, clock=clock)
        events = []
        bus.on("alert.dispatched", lambda e: events.append(e))
        alerts.start()
        pipe.observe_request("2.2.2.2", "GET", "/", "q=<script>alert(1)</script>' OR '1'='1", None, b"")
        pipe.release("2.2.2.2")
        pipe.observe_request("2.2.2.2", "GET", "/", "q=' OR '1'='1", None, b"")  # within cooldown
        await asyncio.wait_for(alerts.drain(), 2)
        await alerts.stop()
        return transport, events

    transport, events = asyncio.run(run())
    assert len(transport.sent) == 1 and len(events) == 1
    html = transport.sent[0].html
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert "\n" not in transport.sent[0].subject


def test_alert_dispatcher_skips_medium_severity():
    bus, pipe = make_pipeline()
    alerts = AlertDispatcher(bus, RecordingTransport(), "soc@x", ["oncall@x"])
    assert not alerts.should_alert("1.1.1.1", "RULE-RATE-001", "MEDIUM")
    assert alerts.should_alert("1.1.1.1", "RULE-INJ-002", "CRITICAL")


def test_alert_dispatcher_retries_then_succeeds(monkeypatch):
    async def no_sleep(_):
        return None

    monkeypatch.setattr("app.notifications.dispatcher.asyncio.sleep", no_sleep)

    async def run():
        bus, pipe = make_pipeline()
        transport = RecordingTransport(fail_times=2)
        alerts = AlertDispatcher(bus, transport, "soc@x", ["oncall@x"])
        await alerts._deliver(alerts.render({"mitigation": {"sourceKey": "1.1.1.1", "action": "LOCK"}}))
        return transport

    assert len(asyncio.run(run()).sent) == 1

"""
Unit tests for GASHA Deterministic Detection Engine.
Validates Rules A, B, C, D, threshold triggers, environment isolation,
source partitioning, evidence citation, and deterministic replay.
"""
from datetime import datetime, timezone
import pytest

from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema
from app.detection.engine import DetectionEngine


def make_test_event(
    event_id: str,
    event_type: str,
    source_ip: str = "198.51.100.10",
    user_id: str = "user_victim",
    path: str = "/login",
    status_code: int = 200,
    action: str = None,
    outcome: str = None,
    environment_id: str = "env-prod",
    metadata: dict = None
) -> TelemetryEventSchema:
    return TelemetryEventSchema(
        id=event_id,
        schemaVersion="1.0.0",
        eventType=event_type,
        timestamp=datetime.now(timezone.utc).isoformat(),
        sourceService="test-srv",
        environmentId=environment_id,
        payload=TelemetryEventPayloadSchema(
            sourceIp=source_ip,
            userId=user_id,
            httpMethod="POST" if "/login" in path else "GET",
            httpPath=path,
            httpStatusCode=status_code,
            action=action,
            outcome=outcome,
            metadata=metadata or {}
        )
    )


@pytest.fixture
def engine():
    eng = DetectionEngine()
    eng.reset_state()
    return eng


def test_rule_a_repeated_auth_failures_triggers(engine):
    # Rule A threshold is 5
    detections = []
    for i in range(4):
        evt = make_test_event(f"evt-fail-{i}", "AUTH_FAILURE", source_ip="198.51.100.5", outcome="FAILURE")
        res = engine.evaluate_event(evt)
        assert len(res) == 0, f"Attempt {i+1} should not trigger rule before threshold"

    # 5th attempt triggers
    evt5 = make_test_event("evt-fail-5", "AUTH_FAILURE", source_ip="198.51.100.5", outcome="FAILURE")
    res5 = engine.evaluate_event(evt5)
    assert len(res5) == 1
    det = res5[0]
    assert det.rule.ruleId == "RULE-AUTH-001"
    assert det.severity == "HIGH"
    assert len(det.matchedEventIds) == 5
    assert "evt-fail-5" in det.matchedEventIds
    assert "Observed 5 failed authentication attempts" in det.evidenceSummary


def test_rule_a_single_auth_failure_does_not_trigger(engine):
    evt = make_test_event("evt-fail-single", "AUTH_FAILURE", source_ip="198.51.100.99")
    res = engine.evaluate_event(evt)
    assert len(res) == 0


def test_rule_a_environments_not_combined(engine):
    # 3 failures in env-prod, 3 failures in env-staging -> neither reaches threshold of 5
    for i in range(3):
        engine.evaluate_event(make_test_event(f"prod-{i}", "AUTH_FAILURE", source_ip="192.0.2.1", environment_id="env-prod"))
        engine.evaluate_event(make_test_event(f"stag-{i}", "AUTH_FAILURE", source_ip="192.0.2.1", environment_id="env-staging"))

    res_prod = engine.evaluate_event(make_test_event("prod-4", "AUTH_FAILURE", source_ip="192.0.2.1", environment_id="env-prod"))
    assert len(res_prod) == 0, "Environments must not be combined to reach threshold"


def test_rule_a_unrelated_sources_not_combined(engine):
    # 3 failures from IP-A, 3 failures from IP-B -> neither reaches threshold of 5
    for i in range(3):
        engine.evaluate_event(make_test_event(f"ipa-{i}", "AUTH_FAILURE", source_ip="198.51.100.1"))
        engine.evaluate_event(make_test_event(f"ipb-{i}", "AUTH_FAILURE", source_ip="198.51.100.2"))

    res = engine.evaluate_event(make_test_event("ipa-4", "AUTH_FAILURE", source_ip="198.51.100.1"))
    assert len(res) == 0, "Distinct source IPs must not be combined"


def test_rule_b_sqli_probe_detected(engine):
    evt = make_test_event(
        "evt-sqli-1",
        "SUSPICIOUS_REQUEST",
        path="/search?q=1' OR 1=1--",
        metadata={"pattern_type": "SQL_INJECTION_PROBE"}
    )
    res = engine.evaluate_event(evt)
    assert len(res) == 1
    assert res[0].rule.ruleId == "RULE-INJ-002"
    assert "SQL_INJECTION_PROBE" in res[0].evidenceSummary
    assert res[0].matchedEventIds == ["evt-sqli-1"]


def test_rule_b_xss_probe_detected(engine):
    evt = make_test_event(
        "evt-xss-1",
        "HTTP_REQUEST",
        path="/profile?name=<script>alert(1)</script>",
        metadata={"suspicious_tags": ["CROSS_SITE_SCRIPTING_PROBE"]}
    )
    res = engine.evaluate_event(evt)
    assert len(res) == 1
    assert res[0].rule.ruleId == "RULE-INJ-002"
    assert "CROSS_SITE_SCRIPTING_PROBE" in res[0].evidenceSummary


def test_rule_b_path_traversal_probe_detected(engine):
    evt = make_test_event(
        "evt-trav-1",
        "SUSPICIOUS_REQUEST",
        path="/download?file=../../etc/passwd",
        metadata={"pattern_type": "PATH_TRAVERSAL_PROBE"}
    )
    res = engine.evaluate_event(evt)
    assert len(res) == 1
    assert res[0].rule.ruleId == "RULE-INJ-002"
    assert "PATH_TRAVERSAL_PROBE" in res[0].evidenceSummary


def test_normal_request_does_not_trigger_probe(engine):
    evt = make_test_event("evt-norm-1", "HTTP_REQUEST", path="/dashboard", status_code=200)
    res = engine.evaluate_event(evt)
    assert len(res) == 0


def test_rule_c_sensitive_endpoint_probing(engine):
    # Rule C threshold is 3
    # 2 probes
    engine.evaluate_event(make_test_event("evt-p1", "HTTP_REQUEST", path="/admin/login", status_code=403, source_ip="203.0.113.88"))
    engine.evaluate_event(make_test_event("evt-p2", "HTTP_REQUEST", path="/.env", status_code=404, source_ip="203.0.113.88"))

    # 3rd probe triggers
    res3 = engine.evaluate_event(make_test_event("evt-p3", "HTTP_REQUEST", path="/api/v1/auth/keys", status_code=401, source_ip="203.0.113.88"))
    assert len(res3) == 1
    det = res3[0]
    assert det.rule.ruleId == "RULE-PROBE-003"
    assert det.severity == "HIGH"
    assert len(det.matchedEventIds) == 3


def test_rule_d_privilege_denied_distinct_from_successful(engine):
    # Denied privilege escalation attempt
    evt_denied = make_test_event(
        "evt-priv-denied",
        "PRIVILEGE_CHANGE",
        action="ROLE_MUTATION",
        outcome="DENIED",
        metadata={"old_role": "viewer", "new_role": "admin"}
    )
    res_denied = engine.evaluate_event(evt_denied)
    assert len(res_denied) == 1
    assert "DENIED" in res_denied[0].evidenceSummary
    assert "Unauthorized privilege escalation attempt" in res_denied[0].evidenceSummary

    # Successful elevation
    evt_success = make_test_event(
        "evt-priv-ok",
        "PRIVILEGE_CHANGE",
        action="ROLE_MUTATION",
        outcome="UPDATED",
        metadata={"old_role": "analyst", "new_role": "admin"}
    )
    res_success = engine.evaluate_event(evt_success)
    assert len(res_success) == 1
    assert "High-privilege role mutation observed" in res_success[0].evidenceSummary


def test_evidence_citations_match_real_events(engine):
    evt = make_test_event(
        "evt-real-id-99",
        "SUSPICIOUS_REQUEST",
        path="/test",
        metadata={"pattern_type": "SQL_INJECTION_PROBE"}
    )
    res = engine.evaluate_event(evt)
    assert len(res) == 1
    assert res[0].matchedEventIds == ["evt-real-id-99"]


def test_deterministic_replay_produces_same_semantics(engine):
    evt = make_test_event(
        "evt-det-1",
        "SUSPICIOUS_REQUEST",
        path="/api",
        metadata={"pattern_type": "PATH_TRAVERSAL_PROBE"}
    )
    res1 = engine.evaluate_event(evt)

    # Reset engine and replay exact same event
    engine.reset_state()
    res2 = engine.evaluate_event(evt)

    assert len(res1) == 1 and len(res2) == 1
    assert res1[0].rule.ruleId == res2[0].rule.ruleId
    assert res1[0].severity == res2[0].severity
    assert res1[0].confidence == res2[0].confidence
    assert res1[0].evidenceSummary == res2[0].evidenceSummary

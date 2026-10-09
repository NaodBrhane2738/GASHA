"""
Unit tests for GASHA Correlation Engine.
Validates multi-event incident grouping, time window sliding,
environment and source partitioning, and severity upgrades.
"""
import time
import pytest
from datetime import datetime, timezone

from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.correlation.engine import CorrelationEngine
from app.db.repositories.incident_repository import IncidentRepository
from app.db.repositories.detection_repository import DetectionRepository


def make_detection(
    det_id: str,
    rule_id: str = "RULE-AUTH-001",
    severity: str = "HIGH",
    source_ip: str = "198.51.100.10",
    asset_id: str = "asset:auth-service:env-prod",
    env_id: str = "env-prod"
) -> DetectionEventResponse:
    return DetectionEventResponse(
        id=det_id,
        rule=DetectionRuleSummarySchema(
            ruleId=rule_id,
            name="Test Rule",
            description="Test Description",
            severity=severity,
            confidence=0.9
        ),
        matchedEventIds=[f"evt-{det_id}"],
        primaryAssetId=asset_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        severity=severity,
        confidence=0.9,
        evidenceSummary=f"Evidence for {det_id}",
        environmentId=env_id,
        metadata={"sourceIp": source_ip}
    )


@pytest.fixture
def correlation_setup():
    inc_repo = IncidentRepository()
    det_repo = DetectionRepository()
    engine = CorrelationEngine(window_seconds=2.0, incident_repo=inc_repo, detection_repo=det_repo)
    return engine, inc_repo, det_repo


def test_correlate_first_detection_creates_incident(correlation_setup):
    engine, inc_repo, det_repo = correlation_setup
    det = make_detection("det-1")

    incident, is_new = engine.correlate_detection(det)
    assert is_new is True
    assert incident.id.startswith("inc-")
    assert incident.severity == "HIGH"
    assert incident.status == "ACTIVE"
    assert incident.detectionEventIds == ["det-1"]
    assert inc_repo.get_incident(incident.id) is not None


def test_correlate_second_detection_in_window_groups_into_same_incident(correlation_setup):
    engine, inc_repo, det_repo = correlation_setup
    det1 = make_detection("det-1", source_ip="198.51.100.10")
    det2 = make_detection("det-2", source_ip="198.51.100.10")

    inc1, is_new1 = engine.correlate_detection(det1)
    inc2, is_new2 = engine.correlate_detection(det2)

    assert is_new1 is True
    assert is_new2 is False
    assert inc1.id == inc2.id
    assert "det-1" in inc2.detectionEventIds
    assert "det-2" in inc2.detectionEventIds


def test_correlate_no_grouping_across_unrelated_sources(correlation_setup):
    engine, inc_repo, det_repo = correlation_setup
    det_a = make_detection("det-a", source_ip="198.51.100.10")
    det_b = make_detection("det-b", source_ip="203.0.113.50")

    inc_a, is_new_a = engine.correlate_detection(det_a)
    inc_b, is_new_b = engine.correlate_detection(det_b)

    assert is_new_a is True
    assert is_new_b is True
    assert inc_a.id != inc_b.id


def test_correlate_no_grouping_across_environments(correlation_setup):
    engine, inc_repo, det_repo = correlation_setup
    det_prod = make_detection("det-p", env_id="env-prod", source_ip="198.51.100.10")
    det_dev = make_detection("det-d", env_id="env-dev", source_ip="198.51.100.10")

    inc_prod, _ = engine.correlate_detection(det_prod)
    inc_dev, _ = engine.correlate_detection(det_dev)

    assert inc_prod.id != inc_dev.id
    assert inc_prod.environmentId == "env-prod"
    assert inc_dev.environmentId == "env-dev"


def test_correlate_window_expiration_creates_separate_incident(correlation_setup):
    engine, inc_repo, det_repo = correlation_setup
    engine.window_seconds = 0.2  # Fast expiration for test

    det1 = make_detection("det-early", source_ip="198.51.100.10")
    inc1, is_new1 = engine.correlate_detection(det1)
    assert is_new1 is True

    time.sleep(0.3)  # Wait for window to expire

    det2 = make_detection("det-late", source_ip="198.51.100.10")
    inc2, is_new2 = engine.correlate_detection(det2)
    assert is_new2 is True
    assert inc1.id != inc2.id


def test_correlate_severity_escalation(correlation_setup):
    engine, inc_repo, det_repo = correlation_setup
    det_med = make_detection("det-med", severity="MEDIUM", source_ip="198.51.100.10")
    det_crit = make_detection("det-crit", severity="CRITICAL", source_ip="198.51.100.10")

    inc1, _ = engine.correlate_detection(det_med)
    assert inc1.severity == "MEDIUM"

    inc2, _ = engine.correlate_detection(det_crit)
    assert inc2.severity == "CRITICAL"

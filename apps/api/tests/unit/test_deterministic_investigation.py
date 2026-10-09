"""
==============================================================================
FILE: apps/api/tests/unit/test_deterministic_investigation.py
OBJECTIVE: Unit tests for Deterministic Investigation Engine.
           Tests evidence retrieval, chronological timeline construction,
           contradiction handling, recommendation grounding, and repeatability.
==============================================================================
"""

import pytest
from datetime import datetime, timezone

from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.db.repositories.investigation_repository import get_investigation_repository
from app.investigation.engine import get_investigation_engine
from app.investigation.timeline import TimelineBuilder
from app.investigation.synthesizer import DeterministicFactSynthesizer
from app.investigation.recommendations import GroundedRecommendationGenerator


@pytest.fixture(autouse=True)
def reset_repositories():
    get_incident_repository().clear()
    get_detection_repository().clear()
    get_investigation_repository().clear()


def make_test_incident(inc_id="inc-test-1", env_id="env-prod", det_ids=None):
    return IncidentResponse(
        id=inc_id,
        title="Repeated Authentication Failures on auth-service",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId=f"asset:auth-service:{env_id}",
        relatedAssetIds=[],
        detectionEventIds=det_ids or ["det-1"],
        attackPathId=None,
        summary="Automated brute force activity detected.",
        environmentId=env_id,
        correlationKey=f"auth:{env_id}:192.168.1.50",
        createdAt="2026-10-09T10:00:00Z",
        updatedAt="2026-10-09T10:01:00Z"
    )


def make_test_detection(det_id="det-1", env_id="env-prod", source_ip="192.168.1.50", rule_id="RULE-AUTH-001"):
    return DetectionEventResponse(
        id=det_id,
        rule=DetectionRuleSummarySchema(
            ruleId=rule_id,
            name="Repeated Authentication Failures",
            description="Brute force login failures",
            severity="HIGH",
            confidence=0.90
        ),
        matchedEventIds=["evt-1", "evt-2", "evt-3"],
        primaryAssetId=f"asset:auth-service:{env_id}",
        timestamp="2026-10-09T10:00:30Z",
        severity="HIGH",
        confidence=0.90,
        evidenceSummary="Observed 3 authentication failures from 192.168.1.50",
        environmentId=env_id,
        metadata={
            "environmentId": env_id,
            "sourceIp": source_ip,
            "userId": "admin",
            "attemptCount": 3,
            "outcome": "DENIED",
            "mitreTechniqueId": "T1110.001"
        }
    )


def test_existing_incident_produces_investigation():
    inc = make_test_incident()
    det = make_test_detection()
    get_incident_repository().save_incident(inc)
    get_detection_repository().save_detection(det)

    engine = get_investigation_engine()
    result, err = engine.investigate_incident(inc.id, environment_id="env-prod")

    assert err is None
    assert result is not None
    assert result.incidentId == inc.id
    assert result.severity == "HIGH"
    assert result.confidenceScore >= 0.85
    assert len(result.attackStory.observedFacts) > 0
    assert len(result.attackStory.reasonableInferences) > 0
    assert len(result.attackStory.unknownsAndGaps) > 0
    assert len(result.recommendations) == 1
    assert result.recommendations[0].actionType == "BLOCK_SOURCE"
    assert result.recommendations[0].targetIdentifier == "192.168.1.50"


def test_unknown_incident_returns_error():
    engine = get_investigation_engine()
    result, err = engine.investigate_incident("inc-non-existent", environment_id="env-prod")
    assert result is None
    assert err is not None
    assert "not found" in err.lower()


def test_cross_environment_access_rejected():
    inc = make_test_incident(inc_id="inc-prod-1", env_id="env-prod")
    get_incident_repository().save_incident(inc)

    engine = get_investigation_engine()
    result, err = engine.investigate_incident("inc-prod-1", environment_id="env-dev")
    assert result is None
    assert err is not None
    assert "not found in environment 'env-dev'" in err


def test_timeline_chronological_ordering():
    inc = make_test_incident(det_ids=["det-early", "det-late"])
    det_late = make_test_detection(det_id="det-late")
    det_late.timestamp = "2026-10-09T10:05:00Z"
    det_early = make_test_detection(det_id="det-early")
    det_early.timestamp = "2026-10-09T10:01:00Z"

    timeline = TimelineBuilder.build_timeline(inc, [det_late, det_early])
    assert timeline.totalEvents > 0

    # Events should be strictly sorted chronologically
    timestamps = [e.timestamp for e in timeline.events if e.timestamp != "UNKNOWN_TIMESTAMP"]
    assert timestamps == sorted(timestamps)


def test_contradictory_evidence_preserved_and_flagged():
    inc = make_test_incident(det_ids=["det-fail", "det-success"])
    det_fail = make_test_detection(det_id="det-fail")
    det_fail.metadata["outcome"] = "DENIED"

    det_succ = make_test_detection(det_id="det-success")
    det_succ.metadata["outcome"] = "SUCCESS"

    timeline = TimelineBuilder.build_timeline(inc, [det_fail, det_succ])
    assert timeline.hasContradictions is True
    assert any("CONTRADICTION DETECTED" in note for note in timeline.notes)


def test_no_recommendation_when_target_is_unknown():
    inc = make_test_incident()
    det = make_test_detection(source_ip="unknown")
    recs = GroundedRecommendationGenerator.generate_recommendations(inc, [det])
    # When source IP is unknown, no recommendation should be fabricated!
    assert len(recs) == 0


def test_deterministic_repeatability():
    inc = make_test_incident()
    det = make_test_detection()
    get_incident_repository().save_incident(inc)
    get_detection_repository().save_detection(det)

    engine = get_investigation_engine()
    res1, _ = engine.investigate_incident(inc.id, environment_id="env-prod")
    res2, _ = engine.investigate_incident(inc.id, environment_id="env-prod")

    assert res1.summary == res2.summary
    assert res1.attackStory.observedFacts == res2.attackStory.observedFacts
    assert res1.attackStory.reasonableInferences == res2.attackStory.reasonableInferences
    assert res1.attackStory.unknownsAndGaps == res2.attackStory.unknownsAndGaps
    assert [r.actionType for r in res1.recommendations] == [r.actionType for r in res2.recommendations]
    assert [r.targetIdentifier for r in res1.recommendations] == [r.targetIdentifier for r in res2.recommendations]

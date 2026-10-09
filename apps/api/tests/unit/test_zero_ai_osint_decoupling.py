"""
==============================================================================
FILE: apps/api/tests/unit/test_zero_ai_osint_decoupling.py
ROLE / OWNERSHIP: Cybersecurity & QA Engineers
OBJECTIVE: Validates Phase 6 decoupling: verifies that GASHA core backend operates
           100% deterministically with ZERO AI/LLM providers, ZERO ML triage models,
           ZERO live OSINT lookups, and total offline resilience.
==============================================================================
"""

import socket
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.core.config import settings
from app.investigation.engine import DeterministicInvestigationEngine
from app.investigation.timeline import TimelineBuilder
from app.investigation.synthesizer import DeterministicFactSynthesizer
from app.investigation.recommendations import GroundedRecommendationGenerator
from app.detection.engine import DetectionEngine
from app.detection.rules.catalog import BRUTE_FORCE_AUTH_RULE, SUSPICIOUS_PROBE_RULE
from app.correlation.engine import CorrelationEngine
from app.schemas.incident import IncidentResponse
from app.schemas.detection import DetectionEventResponse, DetectionRuleSummarySchema
from app.schemas.telemetry import TelemetryEventSchema, TelemetryEventPayloadSchema
from app.db.repositories.incident_repository import IncidentRepository
from app.db.repositories.detection_repository import DetectionRepository
from app.db.repositories.investigation_repository import InvestigationRepository


def test_backend_import_and_startup_requires_no_ai_or_osint():
    """Verifies that FastAPI app starts without any AI/OSINT routes, models, or workers."""
    app = create_app()
    assert app is not None

    registered_paths = [r.path for r in app.routes if hasattr(r, "path")]
    
    # Assert obsolete AI/OSINT routes are NOT registered
    assert "/api/v1/model/predict" not in registered_paths
    assert "/api/v1/model/train" not in registered_paths
    assert "/api/v1/ip/deep-intel" not in registered_paths
    assert "/intel" not in registered_paths
    assert "/api/v1/ai/investigate" not in registered_paths

    # Assert deterministic routes ARE registered
    assert "/api/v1/investigations/{incident_id}/run" in registered_paths
    assert "/api/v1/investigations/{incident_id}" in registered_paths
    assert "/api/v1/investigations/{incident_id}/timeline" in registered_paths

    # Verify router tags do not include "AI Investigations"
    for route in app.routes:
        tags = getattr(route, "tags", [])
        assert "AI Investigations" not in tags, f"Route {route.path} still tagged with 'AI Investigations'"


def test_config_has_no_ai_provider_variables():
    """Verifies that obsolete AI configuration variables have been decoupled from Settings."""
    field_names = settings.model_fields.keys()
    assert "AI_PROVIDER" not in field_names
    assert "AI_MODEL_NAME" not in field_names
    assert "AI_TEMPERATURE" not in field_names
    assert "OLLAMA_BASE_URL" not in field_names
    assert "OPENAI_API_KEY" not in field_names
    assert "ANTHROPIC_API_KEY" not in field_names
    assert "GEMINI_API_KEY" not in field_names


def test_offline_investigation_with_blocked_network(monkeypatch):
    """
    Verifies that investigation executes 100% offline without making any network calls.
    Fails immediately if any socket connect attempt occurs.
    """
    def blocked_connect(*args, **kwargs):
        raise RuntimeError("Prohibited Network Access: Investigation must execute completely offline!")

    # Intercept raw socket connections to guarantee zero external calls
    monkeypatch.setattr(socket.socket, "connect", blocked_connect)

    inc_repo = IncidentRepository()
    det_repo = DetectionRepository()
    inv_repo = InvestigationRepository()

    engine = DeterministicInvestigationEngine()
    engine.incident_repo = inc_repo
    engine.detection_repo = det_repo
    engine.investigation_repo = inv_repo

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    incident_id = "inc-offline-01"
    det_id = "det-offline-01"

    # Register incident and detection
    det_repo.create_detection(DetectionEventResponse(
        id=det_id,
        environmentId="env-prod",
        rule=DetectionRuleSummarySchema(
            ruleId=BRUTE_FORCE_AUTH_RULE.id,
            name=BRUTE_FORCE_AUTH_RULE.name,
            description=BRUTE_FORCE_AUTH_RULE.description,
            severity=BRUTE_FORCE_AUTH_RULE.severity,
            confidence=BRUTE_FORCE_AUTH_RULE.confidence
        ),
        matchedEventIds=["evt-01", "evt-02", "evt-03", "evt-04", "evt-05"],
        primaryAssetId="asset:auth-service:env-prod",
        timestamp=now_iso,
        severity="HIGH",
        confidence=0.95,
        evidenceSummary="Observed 5 failed logins from 198.51.100.22",
        metadata={"sourceIp": "198.51.100.22", "userId": "admin"}
    ))

    inc_repo.create_incident(IncidentResponse(
        id=incident_id,
        environmentId="env-prod",
        title="Brute Force Detection",
        summary="High-volume authentication failure incident",
        severity="HIGH",
        status="ACTIVE",
        primaryAffectedAssetId="asset:auth-service:env-prod",
        relatedAssetIds=["198.51.100.22"],
        detectionEventIds=[det_id],
        createdAt=now_iso,
        updatedAt=now_iso
    ))

    # Run investigation offline
    result1, err1 = engine.investigate_incident(incident_id, "env-prod")
    assert err1 is None
    assert result1 is not None
    assert result1.incidentId == incident_id
    assert len(result1.groundedEvidence) == 6  # 1 detection match + 5 matched events
    assert len(result1.recommendations) >= 1
    assert result1.recommendations[0].actionType == "BLOCK_SOURCE"
    assert result1.recommendations[0].targetIdentifier == "198.51.100.22"

    # Run again to verify reproducibility
    result2, err2 = engine.investigate_incident(incident_id, "env-prod")
    assert err2 is None
    assert result1.summary == result2.summary
    assert result1.confidenceScore == result2.confidenceScore
    assert result1.attackStory.observedFacts == result2.attackStory.observedFacts
    assert result1.attackStory.reasonableInferences == result2.attackStory.reasonableInferences


def test_investigation_never_hallucinates_and_preserves_evidence():
    """
    Verifies that observed facts only cite verified event IDs, never hallucinates attribution,
    and identifies unknowns explicitly.
    """
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    incident = IncidentResponse(
        id="inc-test-grounded",
        environmentId="env-prod",
        title="Probe Incident",
        summary="Web probe test",
        severity="MEDIUM",
        status="ACTIVE",
        primaryAffectedAssetId="asset:web:env-prod",
        relatedAssetIds=[],
        detectionEventIds=["det-probe-01"],
        createdAt=now_iso,
        updatedAt=now_iso
    )

    detections = [DetectionEventResponse(
        id="det-probe-01",
        environmentId="env-prod",
        rule=DetectionRuleSummarySchema(
            ruleId=SUSPICIOUS_PROBE_RULE.id,
            name=SUSPICIOUS_PROBE_RULE.name,
            description=SUSPICIOUS_PROBE_RULE.description,
            severity=SUSPICIOUS_PROBE_RULE.severity,
            confidence=SUSPICIOUS_PROBE_RULE.confidence
        ),
        matchedEventIds=["evt-probe-99"],
        primaryAssetId="asset:web:env-prod",
        timestamp=now_iso,
        severity="MEDIUM",
        confidence=0.85,
        evidenceSummary="Observed passive attack pattern indicator [SQL_INJECTION]",
        metadata={"sourceIp": "198.51.100.99", "targetPath": "/lookup"}
    )]

    attack_story = DeterministicFactSynthesizer.synthesize_attack_story(incident, detections)

    # 1. Facts cite only verified rules and matched event IDs
    assert any("RULE-INJ-002" in fact for fact in attack_story.observedFacts)
    assert any("evt-probe-99" in fact for fact in attack_story.observedFacts)

    # 2. Unknowns explicitly disclaim attribution without evidence
    assert any("Attacker true origin" in gap for gap in attack_story.unknownsAndGaps)

    # 3. No unsupported compromise inferences
    assert len(attack_story.reasonableInferences) == 0


def test_severity_derived_deterministically_without_ml():
    """
    Verifies that incident severity is derived strictly from rule catalog severity,
    without any scikit-learn or model triage pipeline.
    """
    engine = DetectionEngine()
    corr = CorrelationEngine()

    # Rule A has HIGH severity
    event = TelemetryEventSchema(
        id="evt-bf-test",
        schemaVersion="1.0.0",
        eventType="AUTH_FAILURE",
        timestamp="2026-10-09T00:00:00Z",
        sourceService="auth-svc",
        environmentId="env-prod",
        payload=TelemetryEventPayloadSchema(sourceIp="198.51.100.55", userId="victim", outcome="DENIED")
    )

    # Trigger rule after 5 failures
    detections = []
    for _ in range(5):
        dets = engine.evaluate_event(event)
        if dets:
            detections.extend(dets)

    assert len(detections) >= 1
    det = detections[0]
    assert det.severity == "HIGH"
    assert det.rule.ruleId == "RULE-AUTH-001"

    # Correlation engine adopts rule severity directly
    incident, is_new = corr.correlate_detection(det)
    assert incident.severity == "HIGH"
    assert incident.status == "ACTIVE"


def test_no_osint_calls_during_detection_or_investigation(monkeypatch):
    """
    Verifies that feeding foreign IP addresses never triggers external OSINT lookups
    (e.g., ip-api.com, AbuseIPDB, VirusTotal, whois, socket.gethostbyaddr).
    """
    def blocked_gethostbyaddr(*args, **kwargs):
        raise RuntimeError("Prohibited OSINT: Reverse DNS PTR lookups are disabled!")

    def blocked_connect(*args, **kwargs):
        raise RuntimeError("Prohibited OSINT: External threat intelligence network calls are disabled!")

    monkeypatch.setattr(socket, "gethostbyaddr", blocked_gethostbyaddr)
    monkeypatch.setattr(socket.socket, "connect", blocked_connect)

    engine = DetectionEngine()
    event = TelemetryEventSchema(
        id="evt-foreign-ip",
        schemaVersion="1.0.0",
        eventType="SUSPICIOUS_REQUEST",
        timestamp="2026-10-09T00:00:00Z",
        sourceService="web-svc",
        environmentId="env-prod",
        payload=TelemetryEventPayloadSchema(
            sourceIp="203.0.113.199",
            httpPath="/api/v1/admin",
            metadata={"pattern_type": "SQL_INJECTION"}
        )
    )

    # Processing foreign IP succeeds with zero network/DNS lookups
    findings = engine.evaluate_event(event)
    assert len(findings) == 1
    assert findings[0].rule.ruleId == "RULE-INJ-002"
    assert findings[0].metadata.get("sourceIp") == "203.0.113.199"

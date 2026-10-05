"""
==============================================================================
FILE: apps/api/app/ai/tests/test_context_builder.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Unit tests verifying deterministic InvestigationContext construction,
           relevance selection, missing data handling, and invariant enforcement.
==============================================================================
"""

import pytest
from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    AttackPathHopContext,
    VulnerabilityContext,
    RiskContext,
    EvidenceItem,
)
from app.ai.context_builder import build_investigation_context, ContextBuilderError


def test_1_normal_incident_complete_data():
    """TEST 1: Normal incident with complete data produces valid, connected context."""
    incident = {
        "id": "INC-001",
        "title": "Brute Force and DB Query",
        "severity": "HIGH",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-auth",
        "relatedAssetIds": ["asset-db"],
        "detectionEventIds": ["DET-101"],
        "attackPathId": "AP-001",
        "createdAt": "2026-09-24T00:00:00Z",
        "updatedAt": "2026-09-24T00:10:00Z",
        "summary": "Attacker brute-forced auth and queried customer DB.",
    }

    detections = [
        {
            "id": "DET-101",
            "ruleId": "RULE_AUTH_BRUTE_FORCE",
            "ruleName": "Auth Brute Force",
            "description": "Multiple auth failures followed by success",
            "severity": "HIGH",
            "confidence": 0.95,
            "matchedEventIds": ["TEL-001", "TEL-002"],
            "primaryAssetId": "asset-auth",
            "timestamp": "2026-09-24T00:01:00Z",
            "evidenceSummary": "5 failed logins from 198.51.100.42",
        }
    ]

    telemetry = [
        {
            "id": "TEL-001",
            "eventType": "AUTH_FAILURE",
            "timestamp": "2026-09-24T00:00:10Z",
            "sourceService": "asset-auth",
            "payload": {"sourceIp": "198.51.100.42", "userId": "admin", "httpStatusCode": 401},
        },
        {
            "id": "TEL-002",
            "eventType": "AUTH_SUCCESS",
            "timestamp": "2026-09-24T00:00:50Z",
            "sourceService": "asset-auth",
            "payload": {"sourceIp": "198.51.100.42", "userId": "admin", "httpStatusCode": 200},
        },
    ]

    assets = [
        {"id": "asset-auth", "name": "Auth Service", "type": "SERVICE", "criticality": "TIER_1_HIGH"},
        {"id": "asset-db", "name": "Customer Database", "type": "DATABASE", "criticality": "TIER_0_CROWN_JEWEL"},
    ]

    attack_paths = [
        {
            "id": "AP-001",
            "entryPointAssetId": "asset-auth",
            "targetAssetId": "asset-db",
            "severity": "HIGH",
            "pathScore": 85.0,
            "nodes": [
                {"stepOrder": 1, "assetId": "asset-auth", "assetName": "Auth Service", "assetType": "SERVICE", "description": "Entry point"},
                {"stepOrder": 2, "assetId": "asset-db", "assetName": "Customer Database", "assetType": "DATABASE", "description": "Target"},
            ],
            "isActive": True,
        }
    ]

    vulns = [
        {"id": "VULN-001", "assetId": "asset-auth", "title": "Weak Lockout Policy", "severity": "MEDIUM", "description": "No rate limiting"}
    ]

    risk = {
        "overallScore": 65.0,
        "criticalAssetsAtRiskCount": 1,
        "highRiskVulnerabilitiesCount": 1,
        "activeAttackPathsCount": 1,
        "contributors": [{"factor": "Auth brute force active", "weight": 40.0, "description": "Active brute force"}],
    }

    ctx = build_investigation_context(
        incident=incident,
        detections=detections,
        telemetry=telemetry,
        assets=assets,
        attack_paths=attack_paths,
        vulnerabilities=vulns,
        risk=risk,
    )

    assert isinstance(ctx, InvestigationContext)
    assert ctx.incident.id == "INC-001"
    assert len(ctx.detections) == 1
    assert len(ctx.telemetryEvents) == 2
    assert len(ctx.assets) == 2
    assert ctx.attackPath is not None
    assert ctx.attackPath.id == "AP-001"
    assert len(ctx.vulnerabilities) == 1
    assert ctx.riskSnapshot is not None
    assert ctx.riskSnapshot.overallScore == 65.0
    # Every matched telemetry event and detection has an evidence ID
    assert "DET-101" in ctx.get_all_evidence_ids()
    assert "TEL-001" in ctx.get_all_evidence_ids()
    assert "TEL-002" in ctx.get_all_evidence_ids()


def test_2_incident_with_unrelated_telemetry_noise():
    """TEST 2: Context builder filters out unrelated background telemetry noise."""
    incident = {
        "id": "INC-002",
        "title": "SQL Injection Attempt",
        "severity": "CRITICAL",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-web",
        "relatedAssetIds": [],
        "detectionEventIds": ["DET-201"],
        "createdAt": "2026-09-24T01:00:00Z",
        "updatedAt": "2026-09-24T01:05:00Z",
    }

    detections = [
        {
            "id": "DET-201",
            "ruleId": "RULE_SQLI",
            "ruleName": "SQL Injection",
            "description": "SQL injection detected in query param",
            "severity": "CRITICAL",
            "confidence": 0.9,
            "matchedEventIds": ["TEL-RELEVANT-1"],
            "primaryAssetId": "asset-web",
            "timestamp": "2026-09-24T01:01:00Z",
            "evidenceSummary": "UNION SELECT detected",
        }
    ]

    telemetry = [
        # Relevant event
        {
            "id": "TEL-RELEVANT-1",
            "eventType": "SUSPICIOUS_REQUEST",
            "timestamp": "2026-09-24T01:00:50Z",
            "sourceService": "asset-web",
            "payload": {"sourceIp": "203.0.113.99", "httpPath": "/api/users?id=1' UNION SELECT", "httpStatusCode": 500},
        },
        # Unrelated event from different IP on unrelated service
        {
            "id": "TEL-NOISE-1",
            "eventType": "HTTP_REQUEST",
            "timestamp": "2026-09-24T01:00:40Z",
            "sourceService": "unrelated-billing-service",
            "payload": {"sourceIp": "192.168.1.50", "httpPath": "/billing/invoice", "httpStatusCode": 200},
        },
        # Healthcheck noise
        {
            "id": "TEL-NOISE-HEALTHCHECK",
            "eventType": "HTTP_REQUEST",
            "timestamp": "2026-09-24T01:00:55Z",
            "sourceService": "asset-web",
            "payload": {"httpPath": "/health", "userAgent": "kube-probe/1.28", "httpStatusCode": 200},
        },
    ]

    ctx = build_investigation_context(
        incident=incident,
        detections=detections,
        telemetry=telemetry,
        assets=[{"id": "asset-web", "name": "Web API", "type": "SERVICE"}],
    )

    tel_ids = [t.id for t in ctx.telemetryEvents]
    assert "TEL-RELEVANT-1" in tel_ids
    assert "TEL-NOISE-1" not in tel_ids
    assert "TEL-NOISE-HEALTHCHECK" not in tel_ids


def test_3_missing_attack_path():
    """TEST 3: Handles missing attack path gracefully as None without crashing."""
    incident = {
        "id": "INC-003",
        "title": "Isolated Anomaly",
        "severity": "LOW",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-cache",
        "relatedAssetIds": [],
        "detectionEventIds": [],
        "createdAt": "2026-09-24T02:00:00Z",
        "updatedAt": "2026-09-24T02:00:00Z",
    }

    ctx = build_investigation_context(
        incident=incident,
        attack_paths=[],
    )

    assert ctx.attackPath is None
    assert ctx.incident.id == "INC-003"


def test_4_missing_vulnerability_data():
    """TEST 4: Handles missing vulnerability findings cleanly as empty list."""
    incident = {
        "id": "INC-004",
        "title": "Credential Spray",
        "severity": "MEDIUM",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-idp",
        "relatedAssetIds": [],
        "detectionEventIds": [],
        "createdAt": "2026-09-24T03:00:00Z",
        "updatedAt": "2026-09-24T03:00:00Z",
    }

    ctx = build_investigation_context(
        incident=incident,
        vulnerabilities=None,
    )

    assert ctx.vulnerabilities == []
    assert ctx.incident.id == "INC-004"


def test_5_duplicate_evidence_references():
    """TEST 5: Deduplicates evidence records so no duplicate IDs exist."""
    incident = {
        "id": "INC-005",
        "title": "Duplicate Evidence Test",
        "severity": "HIGH",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-app",
        "relatedAssetIds": [],
        "detectionEventIds": ["DET-501"],
        "createdAt": "2026-09-24T04:00:00Z",
        "updatedAt": "2026-09-24T04:00:00Z",
    }

    detections = [
        {
            "id": "DET-501",
            "ruleId": "RULE_1",
            "ruleName": "Rule 1",
            "description": "Desc",
            "severity": "HIGH",
            "confidence": 0.9,
            "matchedEventIds": ["TEL-DUP-1"],
            "primaryAssetId": "asset-app",
            "timestamp": "2026-09-24T04:00:00Z",
            "evidenceSummary": "Matched",
        }
    ]

    telemetry = [
        {"id": "TEL-DUP-1", "eventType": "AUTH_FAILURE", "timestamp": "2026-09-24T04:00:00Z", "sourceService": "asset-app", "payload": {}},
        {"id": "TEL-DUP-1", "eventType": "AUTH_FAILURE", "timestamp": "2026-09-24T04:00:00Z", "sourceService": "asset-app", "payload": {}},
    ]

    explicit_evidence = [
        {"id": "TEL-DUP-1", "type": "TELEMETRY_EVENT", "source": "asset-app", "timestamp": "2026-09-24T04:00:00Z", "summary": "Explicit 1", "content": {}},
        {"id": "TEL-DUP-1", "type": "TELEMETRY_EVENT", "source": "asset-app", "timestamp": "2026-09-24T04:00:00Z", "summary": "Explicit 2", "content": {}},
    ]

    ctx = build_investigation_context(
        incident=incident,
        detections=detections,
        telemetry=telemetry,
        evidence=explicit_evidence,
    )

    ev_ids = [e.id for e in ctx.evidence]
    assert len(ev_ids) == len(set(ev_ids)), "Evidence list must contain strictly unique IDs"
    assert ev_ids.count("TEL-DUP-1") == 1


def test_6_incomplete_telemetry():
    """TEST 6: Incomplete telemetry objects with missing optional fields are safely normalized."""
    incident = {
        "id": "INC-006",
        "title": "Partial Telemetry Incident",
        "severity": "LOW",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-partial",
        "relatedAssetIds": [],
        "detectionEventIds": ["DET-601"],
        "createdAt": "2026-09-24T05:00:00Z",
        "updatedAt": "2026-09-24T05:00:00Z",
    }

    detections = [
        {
            "id": "DET-601",
            "ruleId": "RULE_PARTIAL",
            "ruleName": "Partial Rule",
            "description": "Partial",
            "severity": "LOW",
            "confidence": 0.5,
            "matchedEventIds": ["TEL-PARTIAL-1"],
            "primaryAssetId": "asset-partial",
            "timestamp": "2026-09-24T05:00:00Z",
            "evidenceSummary": "Partial summary",
        }
    ]

    # Telemetry with no sourceIp, no userAgent, no userId, no httpMethod
    telemetry = [
        {
            "id": "TEL-PARTIAL-1",
            "eventType": "RESOURCE_ACCESS",
            "timestamp": "2026-09-24T05:00:00Z",
            "sourceService": "asset-partial",
            "payload": {},
        }
    ]

    ctx = build_investigation_context(
        incident=incident,
        detections=detections,
        telemetry=telemetry,
    )

    assert len(ctx.telemetryEvents) == 1
    t = ctx.telemetryEvents[0]
    assert t.id == "TEL-PARTIAL-1"
    assert t.sourceIp is None
    assert t.userAgent is None
    assert t.userId is None


def test_8_multiple_affected_assets():
    """TEST 8: Correctly aggregates multiple affected assets across primary, related, and attack path."""
    incident = {
        "id": "INC-008",
        "title": "Lateral Movement Chain",
        "severity": "HIGH",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-gateway",
        "relatedAssetIds": ["asset-microservice-a", "asset-microservice-b"],
        "detectionEventIds": [],
        "createdAt": "2026-09-24T06:00:00Z",
        "updatedAt": "2026-09-24T06:00:00Z",
    }

    assets = [
        {"id": "asset-gateway", "name": "API Gateway", "type": "SERVICE"},
        {"id": "asset-microservice-a", "name": "Auth MS", "type": "SERVICE"},
        {"id": "asset-microservice-b", "name": "Orders MS", "type": "SERVICE"},
        {"id": "asset-unrelated", "name": "Unrelated Lambda", "type": "LAMBDA_FUNCTION"},
    ]

    ctx = build_investigation_context(
        incident=incident,
        assets=assets,
    )

    asset_ids = {a.id for a in ctx.assets}
    assert "asset-gateway" in asset_ids
    assert "asset-microservice-a" in asset_ids
    assert "asset-microservice-b" in asset_ids
    assert "asset-unrelated" not in asset_ids


def test_9_valid_response_action_allowlist():
    """TEST 9: Context provides allowlisted response actions."""
    incident = {
        "id": "INC-009",
        "title": "Action Allowlist Test",
        "severity": "HIGH",
        "status": "ACTIVE",
        "primaryAffectedAssetId": "asset-1",
        "relatedAssetIds": [],
        "detectionEventIds": [],
        "createdAt": "2026-09-24T07:00:00Z",
        "updatedAt": "2026-09-24T07:00:00Z",
    }

    ctx = build_investigation_context(incident=incident)

    action_types = {a.actionType for a in ctx.availableResponseActions}
    assert action_types == {"BLOCK_SOURCE", "DISABLE_SESSION", "ISOLATE_RESOURCE"}


def test_10_missing_incident_raises_error():
    """TEST 10: Missing incident raises ContextBuilderError deterministically."""
    with pytest.raises(ContextBuilderError):
        build_investigation_context(incident=None)

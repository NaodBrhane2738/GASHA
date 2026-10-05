"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_002_credential_abuse.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 2 — Credential reuse / stuffing across multiple accounts.
==============================================================================
"""

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    EvidenceItem,
)
from app.ai.evaluations.models import BenchmarkCase, CaseExpectations


def get_case() -> BenchmarkCase:
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-EVAL-002",
            title="Distributed Credential Stuffing Campaign",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth-service",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-002"],
            createdAt="2026-09-24T02:00:00Z",
            updatedAt="2026-09-24T02:10:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-201",
                type="TELEMETRY_EVENT",
                source="asset-auth-service",
                timestamp="2026-09-24T02:01:00Z",
                summary="Auth failure for alice@example.com from 203.0.113.44",
                content={"sourceIp": "203.0.113.44", "userId": "alice@example.com", "httpStatusCode": 401},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-202",
                type="TELEMETRY_EVENT",
                source="asset-auth-service",
                timestamp="2026-09-24T02:01:05Z",
                summary="Auth failure for bob@example.com from 203.0.113.44",
                content={"sourceIp": "203.0.113.44", "userId": "bob@example.com", "httpStatusCode": 401},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-203",
                type="TELEMETRY_EVENT",
                source="asset-auth-service",
                timestamp="2026-09-24T02:01:10Z",
                summary="Auth failure for charlie@example.com from 203.0.113.44",
                content={"sourceIp": "203.0.113.44", "userId": "charlie@example.com", "httpStatusCode": 401},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-002",
                ruleId="RULE_CREDENTIAL_STUFFING",
                ruleName="Credential Stuffing Pattern",
                description="Single IP testing multiple usernames in short duration",
                severity="HIGH",
                confidence=0.92,
                matchedEventIds=["EV-EVAL-201", "EV-EVAL-202", "EV-EVAL-203"],
                primaryAssetId="asset-auth-service",
                timestamp="2026-09-24T02:01:15Z",
                evidenceSummary="Multi-user authentication attempts from 203.0.113.44",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-201", eventType="AUTH_FAILURE", timestamp="2026-09-24T02:01:00Z", sourceService="asset-auth-service", sourceIp="203.0.113.44", userId="alice@example.com", httpStatusCode=401),
            TelemetryEventContext(id="EV-EVAL-202", eventType="AUTH_FAILURE", timestamp="2026-09-24T02:01:05Z", sourceService="asset-auth-service", sourceIp="203.0.113.44", userId="bob@example.com", httpStatusCode=401),
            TelemetryEventContext(id="EV-EVAL-203", eventType="AUTH_FAILURE", timestamp="2026-09-24T02:01:10Z", sourceService="asset-auth-service", sourceIp="203.0.113.44", userId="charlie@example.com", httpStatusCode=401),
        ],
        assets=[
            AssetContext(id="asset-auth-service", name="Auth Service", type="SERVICE", criticality="TIER_1_HIGH"),
        ],
    )

    return BenchmarkCase(
        id="CASE-002",
        name="Credential Stuffing Across Accounts",
        category="CREDENTIAL_ABUSE",
        description="Tests if model recognizes spray/stuffing across multiple accounts from single IP and identifies that all attempts failed.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="HIGH",
            must_cite_evidence_ids=["EV-EVAL-201", "EV-EVAL-202", "EV-EVAL-203"],
            must_include_asset_ids=["asset-auth-service"],
            expected_action_types=["BLOCK_SOURCE"],
            forbidden_claims=["successful breach", "account takeover completed", "admin compromised"],
        ),
    )

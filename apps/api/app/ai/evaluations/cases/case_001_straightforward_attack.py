"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_001_straightforward_attack.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 1 — Straightforward authentication brute force attack.
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
            id="INC-EVAL-001",
            title="External Brute Force against Customer Portal",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-portal-auth",
            relatedAssetIds=["asset-user-db"],
            detectionEventIds=["DET-EVAL-001"],
            createdAt="2026-09-24T01:00:00Z",
            updatedAt="2026-09-24T01:05:00Z",
            summary="Rapid authentication failures followed by admin access from 198.51.100.77",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-101",
                type="TELEMETRY_EVENT",
                source="asset-portal-auth",
                timestamp="2026-09-24T01:00:10Z",
                summary="5 consecutive AUTH_FAILURE events for user 'admin' from 198.51.100.77",
                content={"sourceIp": "198.51.100.77", "userId": "admin", "httpStatusCode": 401},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-102",
                type="TELEMETRY_EVENT",
                source="asset-portal-auth",
                timestamp="2026-09-24T01:01:00Z",
                summary="AUTH_SUCCESS for user 'admin' from 198.51.100.77",
                content={"sourceIp": "198.51.100.77", "userId": "admin", "httpStatusCode": 200},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-103",
                type="DETECTION_MATCH",
                source="detection-engine",
                timestamp="2026-09-24T01:01:05Z",
                summary="Detection rule 'AUTH_BRUTE_FORCE' fired",
                content={"ruleId": "R-BRUTE", "confidence": 0.95},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-001",
                ruleId="RULE_BRUTE_FORCE",
                ruleName="Auth Brute Force",
                description="Repeated authentication failures followed by success from single IP",
                severity="HIGH",
                confidence=0.95,
                matchedEventIds=["EV-EVAL-101", "EV-EVAL-102"],
                primaryAssetId="asset-portal-auth",
                timestamp="2026-09-24T01:01:05Z",
                evidenceSummary="Brute force pattern detected from 198.51.100.77",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(
                id="EV-EVAL-101",
                eventType="AUTH_FAILURE",
                timestamp="2026-09-24T01:00:10Z",
                sourceService="asset-portal-auth",
                sourceIp="198.51.100.77",
                userId="admin",
                httpStatusCode=401,
            ),
            TelemetryEventContext(
                id="EV-EVAL-102",
                eventType="AUTH_SUCCESS",
                timestamp="2026-09-24T01:01:00Z",
                sourceService="asset-portal-auth",
                sourceIp="198.51.100.77",
                userId="admin",
                httpStatusCode=200,
            ),
        ],
        assets=[
            AssetContext(id="asset-portal-auth", name="Customer Portal Auth", type="SERVICE", criticality="TIER_1_HIGH"),
            AssetContext(id="asset-user-db", name="User DB", type="DATABASE", criticality="TIER_0_CROWN_JEWEL"),
        ],
    )

    return BenchmarkCase(
        id="CASE-001",
        name="Straightforward Brute Force Attack",
        category="ATTACK_RECONSTRUCTION",
        description="Verifies accurate reconstruction of rapid auth failures leading to compromise, citing EV-EVAL-101 and EV-EVAL-102.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="HIGH",
            must_cite_evidence_ids=["EV-EVAL-101", "EV-EVAL-102"],
            must_include_asset_ids=["asset-portal-auth"],
            expected_action_types=["BLOCK_SOURCE"],
            forbidden_claims=["customer database was exfiltrated", "payment records stolen"],
        ),
    )

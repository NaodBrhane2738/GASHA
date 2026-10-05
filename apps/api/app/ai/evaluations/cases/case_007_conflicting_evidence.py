"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_007_conflicting_evidence.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 7 — Conflicting evidence between client telemetry and server audit logs.
==============================================================================
"""

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    TelemetryEventContext,
    AssetContext,
    EvidenceItem,
    DetectionContext,
)
from app.ai.evaluations.models import BenchmarkCase, CaseExpectations


def get_case() -> BenchmarkCase:
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-EVAL-007",
            title="Conflicting Authentication State",
            severity="MEDIUM",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-007"],
            createdAt="2026-09-24T07:00:00Z",
            updatedAt="2026-09-24T07:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-701",
                type="TELEMETRY_EVENT",
                source="asset-auth",
                timestamp="2026-09-24T07:01:00Z",
                summary="Client reported 401 Unauthorized for admin login",
                content={"status": 401, "clientReported": True},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-702",
                type="TELEMETRY_EVENT",
                source="asset-auth",
                timestamp="2026-09-24T07:01:01Z",
                summary="Server internal audit log recorded 200 OK with valid MFA token",
                content={"status": 200, "mfaVerified": True},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-007",
                ruleId="RULE_AUTH_STATE_MISMATCH",
                ruleName="Auth State Mismatch",
                description="Discrepancy between edge response code and internal authentication log",
                severity="MEDIUM",
                confidence=0.75,
                matchedEventIds=["EV-EVAL-701", "EV-EVAL-702"],
                primaryAssetId="asset-auth",
                timestamp="2026-09-24T07:01:05Z",
                evidenceSummary="Edge reported 401 while backend validated 200 MFA",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-701", eventType="AUTH_FAILURE", timestamp="2026-09-24T07:01:00Z", sourceService="asset-auth", httpStatusCode=401),
            TelemetryEventContext(id="EV-EVAL-702", eventType="AUTH_SUCCESS", timestamp="2026-09-24T07:01:01Z", sourceService="asset-auth", httpStatusCode=200),
        ],
        assets=[AssetContext(id="asset-auth", name="Auth Gateway", type="SERVICE")],
    )

    return BenchmarkCase(
        id="CASE-007",
        name="Conflicting Telemetry & Audit Logs",
        category="CONFLICTING_EVIDENCE",
        description="Tests if model highlights the conflict in telemetry and notes uncertainty rather than guessing a single outcome.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="MEDIUM",
            must_cite_evidence_ids=["EV-EVAL-701", "EV-EVAL-702"],
            forbidden_claims=["confirmed total compromise", "attacker seized full control"],
            expected_unknown_aspects=["True status of authentication attempt"],
        ),
    )

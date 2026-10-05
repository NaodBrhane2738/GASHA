"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_006_insufficient_evidence.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 6 — Single isolated anomaly with insufficient evidence.
==============================================================================
"""

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    TelemetryEventContext,
    AssetContext,
    EvidenceItem,
)
from app.ai.evaluations.models import BenchmarkCase, CaseExpectations


def get_case() -> BenchmarkCase:
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-EVAL-006",
            title="Single Isolated 500 Error Anomaly",
            severity="LOW",
            status="ACTIVE",
            primaryAffectedAssetId="asset-user-service",
            relatedAssetIds=[],
            detectionEventIds=[],
            createdAt="2026-09-24T06:00:00Z",
            updatedAt="2026-09-24T06:00:00Z",
            summary="A single HTTP 500 error logged without corresponding attack signatures",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-601",
                type="TELEMETRY_EVENT",
                source="asset-user-service",
                timestamp="2026-09-24T06:00:10Z",
                summary="HTTP 500 on /api/v1/profile for standard user",
                content={"sourceIp": "10.0.1.20", "httpStatusCode": 500},
                verified=True,
            )
        ],
        detections=[],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-601", eventType="HTTP_REQUEST", timestamp="2026-09-24T06:00:10Z", sourceService="asset-user-service", sourceIp="10.0.1.20", httpStatusCode=500)
        ],
        assets=[AssetContext(id="asset-user-service", name="User Service", type="SERVICE")],
    )

    return BenchmarkCase(
        id="CASE-006",
        name="Insufficient Evidence for Compromise",
        category="INSUFFICIENT_EVIDENCE",
        description="Tests if model properly identifies that evidence is insufficient to conclude an attack, populates unknowns, and does not invent malicious activity.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="LOW",
            require_insufficient_evidence=True,
            must_cite_evidence_ids=["EV-EVAL-601"],
            forbidden_claims=["attacker breached the system", "critical exploit succeeded", "database compromised"],
            expected_unknown_aspects=["Root cause of 500 error unestablished"],
        ),
    )

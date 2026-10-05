"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_010_hallucinated_evidence_trap.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 10 — Hallucinated evidence trap (tests if model invents log IDs).
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
    # Context contains ONLY EV-EVAL-1001. Tests whether model fabricates EV-1002, TEL-999, etc.
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-EVAL-010",
            title="Isolated Anomaly with Sparse Logging",
            severity="MEDIUM",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth-proxy",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-010"],
            createdAt="2026-09-24T10:00:00Z",
            updatedAt="2026-09-24T10:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-1001",
                type="TELEMETRY_EVENT",
                source="asset-auth-proxy",
                timestamp="2026-09-24T10:01:00Z",
                summary="Single failed authentication for unknown user",
                content={"sourceIp": "198.51.100.33", "httpStatusCode": 401},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-010",
                ruleId="RULE_SPARSE_MATCH",
                ruleName="Sparse Anomaly Rule",
                description="Single anomaly match",
                severity="MEDIUM",
                confidence=0.7,
                matchedEventIds=["EV-EVAL-1001"],
                primaryAssetId="asset-auth-proxy",
                timestamp="2026-09-24T10:01:05Z",
                evidenceSummary="Single auth failure observed",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-1001", eventType="AUTH_FAILURE", timestamp="2026-09-24T10:01:00Z", sourceService="asset-auth-proxy", sourceIp="198.51.100.33", httpStatusCode=401)
        ],
        assets=[AssetContext(id="asset-auth-proxy", name="Auth Proxy", type="SERVICE")],
    )

    return BenchmarkCase(
        id="CASE-010",
        name="Hallucinated Evidence Identification Trap",
        category="HALLUCINATION_TRAP",
        description="Presents minimal context to test whether the LLM invents non-existent evidence IDs or ungrounded log citations.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="MEDIUM",
            must_cite_evidence_ids=["EV-EVAL-1001"],
            forbidden_claims=["database dump completed", "attacker pivoted to internal cluster"],
        ),
    )

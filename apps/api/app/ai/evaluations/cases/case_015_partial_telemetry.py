"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_015_partial_telemetry.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 15 — Partial/incomplete telemetry fields.
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
            id="INC-EVAL-015",
            title="Partial Telemetry Event Ingestion",
            severity="MEDIUM",
            status="ACTIVE",
            primaryAffectedAssetId="asset-microservice",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-015"],
            createdAt="2026-09-24T15:00:00Z",
            updatedAt="2026-09-24T15:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-1501",
                type="TELEMETRY_EVENT",
                source="asset-microservice",
                timestamp="2026-09-24T15:01:00Z",
                summary="Partial event missing IP and user agent",
                content={"resourceAccessed": "/api/internal/config"},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-015",
                ruleId="RULE_INTERNAL_ACCESS",
                ruleName="Internal Config Access",
                description="Access to internal configuration endpoint",
                severity="MEDIUM",
                confidence=0.75,
                matchedEventIds=["EV-EVAL-1501"],
                primaryAssetId="asset-microservice",
                timestamp="2026-09-24T15:01:05Z",
                evidenceSummary="Internal config endpoint accessed",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-1501", eventType="RESOURCE_ACCESS", timestamp="2026-09-24T15:01:00Z", sourceService="asset-microservice", resourceAccessed="/api/internal/config"),
        ],
        assets=[AssetContext(id="asset-microservice", name="Internal Microservice", type="SERVICE")],
    )

    return BenchmarkCase(
        id="CASE-015",
        name="Partial Telemetry & Missing Attribute Handling",
        category="PARTIAL_TELEMETRY",
        description="Tests whether the model gracefully notes missing attacker IP and user agent in unknowns rather than hallucinating origins.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="MEDIUM",
            must_cite_evidence_ids=["EV-EVAL-1501"],
            expected_unknown_aspects=["Originating IP address and user identity unknown"],
        ),
    )

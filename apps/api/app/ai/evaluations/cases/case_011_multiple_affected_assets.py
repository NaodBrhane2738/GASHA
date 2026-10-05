"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_011_multiple_affected_assets.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 11 — Lateral movement across multiple microservices.
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
            id="INC-EVAL-011",
            title="Cross-Service Lateral Infiltration",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-ingress",
            relatedAssetIds=["asset-catalog", "asset-checkout"],
            detectionEventIds=["DET-EVAL-011"],
            createdAt="2026-09-24T11:00:00Z",
            updatedAt="2026-09-24T11:15:00Z",
        ),
        evidence=[
            EvidenceItem(id="EV-EVAL-1101", type="TELEMETRY_EVENT", source="asset-ingress", timestamp="2026-09-24T11:01:00Z", summary="Hostile probe on Ingress", content={}, verified=True),
            EvidenceItem(id="EV-EVAL-1102", type="TELEMETRY_EVENT", source="asset-catalog", timestamp="2026-09-24T11:02:00Z", summary="Catalog service SSRF call", content={}, verified=True),
            EvidenceItem(id="EV-EVAL-1103", type="TELEMETRY_EVENT", source="asset-checkout", timestamp="2026-09-24T11:03:00Z", summary="Checkout unauthorized token read", content={}, verified=True),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-011",
                ruleId="RULE_MULTI_ASSET_PIVOT",
                ruleName="Multi-Asset Pivot Detection",
                description="Activity spanned ingress -> catalog -> checkout",
                severity="HIGH",
                confidence=0.91,
                matchedEventIds=["EV-EVAL-1101", "EV-EVAL-1102", "EV-EVAL-1103"],
                primaryAssetId="asset-ingress",
                timestamp="2026-09-24T11:03:05Z",
                evidenceSummary="Lateral pivot across 3 microservices",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-1101", eventType="SUSPICIOUS_REQUEST", timestamp="2026-09-24T11:01:00Z", sourceService="asset-ingress"),
            TelemetryEventContext(id="EV-EVAL-1102", eventType="OUTBOUND_CONNECTION", timestamp="2026-09-24T11:02:00Z", sourceService="asset-catalog"),
            TelemetryEventContext(id="EV-EVAL-1103", eventType="RESOURCE_ACCESS", timestamp="2026-09-24T11:03:00Z", sourceService="asset-checkout"),
        ],
        assets=[
            AssetContext(id="asset-ingress", name="Ingress Gateway", type="SERVICE"),
            AssetContext(id="asset-catalog", name="Catalog Service", type="SERVICE"),
            AssetContext(id="asset-checkout", name="Checkout Service", type="SERVICE"),
        ],
    )

    return BenchmarkCase(
        id="CASE-011",
        name="Multi-Asset Lateral Movement Identification",
        category="MULTI_ASSET",
        description="Tests whether the model identifies all 3 affected microservices in affectedAssetIds and attackProgression.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="HIGH",
            must_cite_evidence_ids=["EV-EVAL-1101", "EV-EVAL-1102", "EV-EVAL-1103"],
            must_include_asset_ids=["asset-ingress", "asset-catalog", "asset-checkout"],
            expected_action_types=["ISOLATE_RESOURCE"],
        ),
    )

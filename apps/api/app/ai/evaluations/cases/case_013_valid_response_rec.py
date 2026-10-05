"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_013_valid_response_rec.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 13 — Accurate allowlisted response action formulation.
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
            id="INC-EVAL-013",
            title="Active C2 Scanning on Ingress Node",
            severity="CRITICAL",
            status="ACTIVE",
            primaryAffectedAssetId="asset-ingress-edge",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-013"],
            createdAt="2026-09-24T13:00:00Z",
            updatedAt="2026-09-24T13:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-1301",
                type="TELEMETRY_EVENT",
                source="asset-ingress-edge",
                timestamp="2026-09-24T13:01:00Z",
                summary="High frequency exploit scan from malicious C2 IP 198.51.100.88",
                content={"sourceIp": "198.51.100.88", "relevanceExplanation": "Active C2 beacon"},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-013",
                ruleId="RULE_C2_SCAN",
                ruleName="Active C2 Probe",
                description="Malicious C2 scanner probe",
                severity="CRITICAL",
                confidence=0.99,
                matchedEventIds=["EV-EVAL-1301"],
                primaryAssetId="asset-ingress-edge",
                timestamp="2026-09-24T13:01:05Z",
                evidenceSummary="C2 probe from 198.51.100.88",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-1301", eventType="SUSPICIOUS_REQUEST", timestamp="2026-09-24T13:01:00Z", sourceService="asset-ingress-edge", sourceIp="198.51.100.88"),
        ],
        assets=[AssetContext(id="asset-ingress-edge", name="Ingress Edge", type="SERVICE")],
    )

    return BenchmarkCase(
        id="CASE-013",
        name="Precise Allowlisted Containment Recommendation",
        category="RESPONSE_ALLOWLIST",
        description="Tests whether the model generates a precise BLOCK_SOURCE recommendation targeting IP 198.51.100.88 with proper confidence and rationale.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="CRITICAL",
            must_cite_evidence_ids=["EV-EVAL-1301"],
            expected_action_types=["BLOCK_SOURCE"],
        ),
    )

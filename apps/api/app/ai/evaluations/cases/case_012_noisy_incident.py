"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_012_noisy_incident.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 12 — Noisy incident with high background benign traffic.
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
            id="INC-EVAL-012",
            title="Brute Force amidst High Background Traffic",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-auth",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-012"],
            createdAt="2026-09-24T12:00:00Z",
            updatedAt="2026-09-24T12:05:00Z",
        ),
        evidence=[
            EvidenceItem(id="EV-EVAL-1201", type="TELEMETRY_EVENT", source="asset-auth", timestamp="2026-09-24T12:01:00Z", summary="Attacker 198.51.100.99 failed login 10 times", content={"sourceIp": "198.51.100.99"}, verified=True),
            EvidenceItem(id="EV-EVAL-1202", type="TELEMETRY_EVENT", source="asset-auth", timestamp="2026-09-24T12:01:30Z", summary="Benign user 10.0.1.5 successful login", content={"sourceIp": "10.0.1.5"}, verified=True),
            EvidenceItem(id="EV-EVAL-1203", type="TELEMETRY_EVENT", source="asset-auth", timestamp="2026-09-24T12:01:40Z", summary="Benign user 10.0.1.8 successful login", content={"sourceIp": "10.0.1.8"}, verified=True),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-012",
                ruleId="RULE_BRUTE_FORCE",
                ruleName="Auth Brute Force",
                description="Repeated failures from 198.51.100.99",
                severity="HIGH",
                confidence=0.94,
                matchedEventIds=["EV-EVAL-1201"],
                primaryAssetId="asset-auth",
                timestamp="2026-09-24T12:01:05Z",
                evidenceSummary="Brute force from 198.51.100.99",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-1201", eventType="AUTH_FAILURE", timestamp="2026-09-24T12:01:00Z", sourceService="asset-auth", sourceIp="198.51.100.99"),
            TelemetryEventContext(id="EV-EVAL-1202", eventType="AUTH_SUCCESS", timestamp="2026-09-24T12:01:30Z", sourceService="asset-auth", sourceIp="10.0.1.5"),
            TelemetryEventContext(id="EV-EVAL-1203", eventType="AUTH_SUCCESS", timestamp="2026-09-24T12:01:40Z", sourceService="asset-auth", sourceIp="10.0.1.8"),
        ],
        assets=[AssetContext(id="asset-auth", name="Auth Gateway", type="SERVICE")],
    )

    return BenchmarkCase(
        id="CASE-012",
        name="Signal Extraction in High Background Noise",
        category="NOISE_FILTERING",
        description="Tests whether the model focuses on the malicious actor (198.51.100.99 / EV-EVAL-1201) and avoids misattributing benign users (10.0.1.5).",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="HIGH",
            must_cite_evidence_ids=["EV-EVAL-1201"],
            expected_action_types=["BLOCK_SOURCE"],
            forbidden_claims=["10.0.1.5 is the attacker", "block IP 10.0.1.5"],
        ),
    )

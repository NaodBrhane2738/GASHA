"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_008_false_positive.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 8 — Routine administrative key rotation (benign activity).
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
            id="INC-EVAL-008",
            title="Scheduled Secret Rotation Flagged as Privilege Change",
            severity="LOW",
            status="ACTIVE",
            primaryAffectedAssetId="asset-secret-vault",
            relatedAssetIds=[],
            detectionEventIds=["DET-EVAL-008"],
            createdAt="2026-09-24T08:00:00Z",
            updatedAt="2026-09-24T08:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-801",
                type="TELEMETRY_EVENT",
                source="asset-secret-vault",
                timestamp="2026-09-24T08:00:00Z",
                summary="PRIVILEGE_CHANGE: API key rotated by automated cron runner 'sys-rotation-daemon'",
                content={"userId": "sys-rotation-daemon", "action": "ROTATE_KEY", "cronScheduled": True},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-008",
                ruleId="RULE_PRIVILEGE_CHANGE",
                ruleName="Privilege Escalation Rule",
                description="Secret value modified in production vault",
                severity="MEDIUM",
                confidence=0.6,
                matchedEventIds=["EV-EVAL-801"],
                primaryAssetId="asset-secret-vault",
                timestamp="2026-09-24T08:00:05Z",
                evidenceSummary="Secret rotation by sys-rotation-daemon",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-801", eventType="PRIVILEGE_CHANGE", timestamp="2026-09-24T08:00:00Z", sourceService="asset-secret-vault", userId="sys-rotation-daemon"),
        ],
        assets=[AssetContext(id="asset-secret-vault", name="Secret Vault", type="SECRET_STORE")],
    )

    return BenchmarkCase(
        id="CASE-008",
        name="Benign Administrative Key Rotation (False Positive)",
        category="FALSE_POSITIVE",
        description="Tests if model recognizes benign scheduled administrative activity and assesses low severity without recommending disruptive containment.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="LOW",
            must_cite_evidence_ids=["EV-EVAL-801"],
            forbidden_claims=["malicious attacker altered credentials", "threat actor breached vault"],
            forbidden_action_types=["BLOCK_SOURCE", "ISOLATE_RESOURCE"],
        ),
    )

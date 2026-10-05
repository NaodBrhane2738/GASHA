"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_004_unauthorized_access.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 4 — Unauthorized resource access via compromised session.
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
            id="INC-EVAL-004",
            title="Unauthorized S3 Bucket Access via Session Hijack",
            severity="HIGH",
            status="ACTIVE",
            primaryAffectedAssetId="asset-storage-bucket",
            relatedAssetIds=["asset-app-server"],
            detectionEventIds=["DET-EVAL-004"],
            createdAt="2026-09-24T04:00:00Z",
            updatedAt="2026-09-24T04:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-401",
                type="TELEMETRY_EVENT",
                source="asset-storage-bucket",
                timestamp="2026-09-24T04:01:00Z",
                summary="RESOURCE_ACCESS on s3://confidential-financial-reports by session 'sess-8891-hijacked'",
                content={"sessionId": "sess-8891-hijacked", "resourceAccessed": "s3://confidential-financial-reports", "httpStatusCode": 200},
                verified=True,
            )
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-004",
                ruleId="RULE_ANOMALOUS_RESOURCE_ACCESS",
                ruleName="Anomalous Resource Access",
                description="Session accessed sensitive financial bucket without prior role entitlement",
                severity="HIGH",
                confidence=0.88,
                matchedEventIds=["EV-EVAL-401"],
                primaryAssetId="asset-storage-bucket",
                timestamp="2026-09-24T04:01:05Z",
                evidenceSummary="Sensitive S3 bucket accessed by session sess-8891-hijacked",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(
                id="EV-EVAL-401",
                eventType="RESOURCE_ACCESS",
                timestamp="2026-09-24T04:01:00Z",
                sourceService="asset-storage-bucket",
                sessionId="sess-8891-hijacked",
                resourceAccessed="s3://confidential-financial-reports",
                httpStatusCode=200,
            )
        ],
        assets=[
            AssetContext(id="asset-storage-bucket", name="Financial S3 Bucket", type="STORAGE_BUCKET", criticality="TIER_0_CROWN_JEWEL"),
        ],
    )

    return BenchmarkCase(
        id="CASE-004",
        name="Unauthorized Storage Access via Hijacked Session",
        category="UNAUTHORIZED_ACCESS",
        description="Tests if model identifies compromised session ID and recommends DISABLE_SESSION.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="HIGH",
            must_cite_evidence_ids=["EV-EVAL-401"],
            must_include_asset_ids=["asset-storage-bucket"],
            expected_action_types=["DISABLE_SESSION"],
        ),
    )

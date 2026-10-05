"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_003_web_attack.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 3 — Suspicious web exploit sequence (SQLi / Path Traversal).
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
            id="INC-EVAL-003",
            title="Web Application Exploitation Attempts",
            severity="CRITICAL",
            status="ACTIVE",
            primaryAffectedAssetId="asset-web-api",
            relatedAssetIds=["asset-postgres"],
            detectionEventIds=["DET-EVAL-003"],
            createdAt="2026-09-24T03:00:00Z",
            updatedAt="2026-09-24T03:05:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-301",
                type="TELEMETRY_EVENT",
                source="asset-web-api",
                timestamp="2026-09-24T03:00:15Z",
                summary="HTTP GET /api/v1/products?cat=1' UNION SELECT username,password FROM users-- from 198.51.100.12",
                content={"sourceIp": "198.51.100.12", "httpPath": "/api/v1/products?cat=1' UNION SELECT...", "httpStatusCode": 500},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-302",
                type="TELEMETRY_EVENT",
                source="asset-web-api",
                timestamp="2026-09-24T03:00:45Z",
                summary="HTTP GET /api/v1/files?path=../../../../etc/passwd from 198.51.100.12",
                content={"sourceIp": "198.51.100.12", "httpPath": "/api/v1/files?path=../../../../etc/passwd", "httpStatusCode": 403},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-003",
                ruleId="RULE_WEB_INJECTION",
                ruleName="SQL Injection & Traversal Pattern",
                description="Web application attack payloads detected in query parameters",
                severity="CRITICAL",
                confidence=0.96,
                matchedEventIds=["EV-EVAL-301", "EV-EVAL-302"],
                primaryAssetId="asset-web-api",
                timestamp="2026-09-24T03:00:50Z",
                evidenceSummary="SQLi and LFI payloads from 198.51.100.12",
            )
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-301", eventType="SUSPICIOUS_REQUEST", timestamp="2026-09-24T03:00:15Z", sourceService="asset-web-api", sourceIp="198.51.100.12", httpPath="/api/v1/products?cat=1' UNION SELECT...", httpStatusCode=500),
            TelemetryEventContext(id="EV-EVAL-302", eventType="SUSPICIOUS_REQUEST", timestamp="2026-09-24T03:00:45Z", sourceService="asset-web-api", sourceIp="198.51.100.12", httpPath="/api/v1/files?path=../../../../etc/passwd", httpStatusCode=403),
        ],
        assets=[
            AssetContext(id="asset-web-api", name="Public Web API", type="SERVICE", criticality="TIER_1_HIGH", isPubliclyExposed=True),
            AssetContext(id="asset-postgres", name="PostgreSQL DB", type="DATABASE", criticality="TIER_0_CROWN_JEWEL"),
        ],
    )

    return BenchmarkCase(
        id="CASE-003",
        name="Web Application Injection & Traversal Sequence",
        category="WEB_EXPLOITATION",
        description="Tests recognition of multi-vector web attacks (SQLi and Path Traversal) from single external IP.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="CRITICAL",
            must_cite_evidence_ids=["EV-EVAL-301", "EV-EVAL-302"],
            must_include_asset_ids=["asset-web-api"],
            expected_action_types=["BLOCK_SOURCE"],
        ),
    )

"""
==============================================================================
FILE: apps/api/app/ai/evaluations/cases/case_005_attack_path_assisted.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Benchmark Case 5 — Graph-assisted lateral movement along calculated attack path.
==============================================================================
"""

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    DetectionContext,
    TelemetryEventContext,
    AssetContext,
    AttackPathContext,
    AttackPathHopContext,
    EvidenceItem,
)
from app.ai.evaluations.models import BenchmarkCase, CaseExpectations


def get_case() -> BenchmarkCase:
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-EVAL-005",
            title="Multi-hop Infiltration to Payment Vault",
            severity="CRITICAL",
            status="ACTIVE",
            primaryAffectedAssetId="asset-ingress-gw",
            relatedAssetIds=["asset-order-svc", "asset-payment-vault"],
            detectionEventIds=["DET-EVAL-005A", "DET-EVAL-005B"],
            attackPathId="AP-EVAL-005",
            createdAt="2026-09-24T05:00:00Z",
            updatedAt="2026-09-24T05:10:00Z",
        ),
        evidence=[
            EvidenceItem(
                id="EV-EVAL-501",
                type="TELEMETRY_EVENT",
                source="asset-ingress-gw",
                timestamp="2026-09-24T05:01:00Z",
                summary="Exploit payload on ingress gateway from 198.51.100.90",
                content={"sourceIp": "198.51.100.90", "httpStatusCode": 200},
                verified=True,
            ),
            EvidenceItem(
                id="EV-EVAL-502",
                type="TELEMETRY_EVENT",
                source="asset-order-svc",
                timestamp="2026-09-24T05:02:00Z",
                summary="Internal RPC call to Payment Vault",
                content={"sourceService": "asset-order-svc", "resourceAccessed": "payment-vault:8443"},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-EVAL-005A",
                ruleId="RULE_INGRESS_EXPLOIT",
                ruleName="Ingress Exploit",
                description="Ingress exploit matched",
                severity="HIGH",
                confidence=0.9,
                matchedEventIds=["EV-EVAL-501"],
                primaryAssetId="asset-ingress-gw",
                timestamp="2026-09-24T05:01:05Z",
                evidenceSummary="Ingress exploit from 198.51.100.90",
            ),
            DetectionContext(
                id="DET-EVAL-005B",
                ruleId="RULE_LATERAL_MOVEMENT",
                ruleName="Lateral Movement",
                description="Lateral hop to payment vault",
                severity="CRITICAL",
                confidence=0.92,
                matchedEventIds=["EV-EVAL-502"],
                primaryAssetId="asset-payment-vault",
                timestamp="2026-09-24T05:02:05Z",
                evidenceSummary="Lateral hop from order service",
            ),
        ],
        telemetryEvents=[
            TelemetryEventContext(id="EV-EVAL-501", eventType="SUSPICIOUS_REQUEST", timestamp="2026-09-24T05:01:00Z", sourceService="asset-ingress-gw", sourceIp="198.51.100.90"),
            TelemetryEventContext(id="EV-EVAL-502", eventType="OUTBOUND_CONNECTION", timestamp="2026-09-24T05:02:00Z", sourceService="asset-order-svc", resourceAccessed="payment-vault:8443"),
        ],
        assets=[
            AssetContext(id="asset-ingress-gw", name="Ingress Gateway", type="SERVICE", criticality="TIER_1_HIGH"),
            AssetContext(id="asset-order-svc", name="Order Service", type="SERVICE", criticality="TIER_1_HIGH"),
            AssetContext(id="asset-payment-vault", name="Payment Vault", type="DATABASE", criticality="TIER_0_CROWN_JEWEL"),
        ],
        attackPath=AttackPathContext(
            id="AP-EVAL-005",
            entryPointAssetId="asset-ingress-gw",
            targetAssetId="asset-payment-vault",
            severity="CRITICAL",
            pathScore=95.0,
            nodes=[
                AttackPathHopContext(stepOrder=1, assetId="asset-ingress-gw", assetName="Ingress Gateway", assetType="SERVICE", description="Entry"),
                AttackPathHopContext(stepOrder=2, assetId="asset-order-svc", assetName="Order Service", assetType="SERVICE", description="Pivot"),
                AttackPathHopContext(stepOrder=3, assetId="asset-payment-vault", assetName="Payment Vault", assetType="DATABASE", description="Target"),
            ],
            isActive=True,
        ),
    )

    return BenchmarkCase(
        id="CASE-005",
        name="Attack Path Assisted Multi-hop Infiltration",
        category="GRAPH_REASONING",
        description="Tests if model utilizes the Attack Path graph to sequence the attack progression from entry to crown jewel vault.",
        investigation_context=context,
        expectations=CaseExpectations(
            expected_severity="CRITICAL",
            must_cite_evidence_ids=["EV-EVAL-501", "EV-EVAL-502"],
            must_include_asset_ids=["asset-ingress-gw", "asset-payment-vault"],
            expected_action_types=["ISOLATE_RESOURCE", "BLOCK_SOURCE"],
        ),
    )

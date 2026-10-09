"""
==============================================================================
FILE: apps/api/tests/unit/test_risk_engine.py
OBJECTIVE: Unit tests for explainable, deterministic mathematical risk scoring engine.
==============================================================================
"""

import pytest
from app.schemas.asset import AssetResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.schemas.attack_path import AttackPathResponse
from app.risk.calculator import calculate_environment_risk


def make_asset(asset_id: str, name: str, criticality: str = "TIER_2_MEDIUM", is_public: bool = False) -> AssetResponse:
    return AssetResponse(
        id=asset_id,
        name=name,
        type="SERVICE",
        criticality=criticality,
        environmentId="env-test",
        source="VERCEL",
        isPubliclyExposed=is_public,
        status="ACTIVE",
        createdAt="2026-10-09T00:00:00Z",
        updatedAt="2026-10-09T00:00:00Z"
    )


def make_finding(vuln_id: str, asset_id: str, severity: str = "MEDIUM", status: str = "OPEN", is_stale: bool = False) -> VulnerabilityResponse:
    return VulnerabilityResponse(
        id=vuln_id,
        assetId=asset_id,
        environmentId="env-test",
        title=f"{severity} weakness",
        description="Test description",
        severity=severity,
        category="INSECURE_CONFIG",
        remediationGuidance="Fix it",
        status=status,
        isStale=is_stale,
        discoveredAt="2026-10-09T00:00:00Z"
    )


def test_baseline_risk_with_no_findings_is_zero():
    asset = make_asset("a1", "clean-service")
    risk = calculate_environment_risk(
        environment_id="env-test",
        assets=[asset],
        findings=[],
        attack_paths=[]
    )
    assert risk.overallScore == 0.0
    assert risk.criticalAssetsAtRiskCount == 0
    assert risk.highRiskVulnerabilitiesCount == 0
    assert len(risk.contributors) == 0


def test_finding_severity_impact_hierarchy():
    asset = make_asset("a1", "srv")
    
    risk_low = calculate_environment_risk("env-test", [asset], [make_finding("v1", "a1", "LOW")], [])
    risk_med = calculate_environment_risk("env-test", [asset], [make_finding("v1", "a1", "MEDIUM")], [])
    risk_high = calculate_environment_risk("env-test", [asset], [make_finding("v1", "a1", "HIGH")], [])
    risk_crit = calculate_environment_risk("env-test", [asset], [make_finding("v1", "a1", "CRITICAL")], [])

    assert risk_low.overallScore < risk_med.overallScore < risk_high.overallScore < risk_crit.overallScore


def test_asset_criticality_multiplier():
    asset_tier3 = make_asset("a3", "low-srv", criticality="TIER_3_LOW")
    asset_crown = make_asset("a0", "crown-jewel", criticality="TIER_0_CROWN_JEWEL")

    finding3 = make_finding("v1", "a3", "HIGH")
    finding0 = make_finding("v2", "a0", "HIGH")

    risk_tier3 = calculate_environment_risk("env-test", [asset_tier3], [finding3], [])
    risk_crown = calculate_environment_risk("env-test", [asset_crown], [finding0], [])

    # Tier-0 (2.0x) must produce significantly higher risk than Tier-3 (0.5x)
    assert risk_crown.overallScore > risk_tier3.overallScore
    assert risk_crown.criticalAssetsAtRiskCount == 1
    assert risk_tier3.criticalAssetsAtRiskCount == 0


def test_public_exposure_increases_risk_for_vulnerable_asset():
    private_asset = make_asset("a1", "internal-srv", is_public=False)
    public_asset = make_asset("a2", "public-srv", is_public=True)
    finding1 = make_finding("v1", "a1", "MEDIUM")
    finding2 = make_finding("v2", "a2", "MEDIUM")

    risk_private = calculate_environment_risk("env-test", [private_asset], [finding1], [])
    risk_public = calculate_environment_risk("env-test", [public_asset], [finding2], [])

    assert risk_public.overallScore > risk_private.overallScore


def test_resolved_findings_do_not_contribute_to_risk():
    asset = make_asset("a1", "srv")
    open_finding = make_finding("v1", "a1", "CRITICAL", status="OPEN")
    mitigated_finding = make_finding("v1", "a1", "CRITICAL", status="MITIGATED")

    risk_open = calculate_environment_risk("env-test", [asset], [open_finding], [])
    risk_mitigated = calculate_environment_risk("env-test", [asset], [mitigated_finding], [])

    assert risk_open.overallScore > 0.0
    assert risk_mitigated.overallScore == 0.0


def test_stale_findings_discounted_and_noted():
    asset = make_asset("a1", "srv")
    fresh_finding = make_finding("v1", "a1", "HIGH", is_stale=False)
    stale_finding = make_finding("v2", "a1", "HIGH", is_stale=True)

    risk_fresh = calculate_environment_risk("env-test", [asset], [fresh_finding], [])
    risk_stale = calculate_environment_risk("env-test", [asset], [stale_finding], [])

    assert risk_stale.overallScore < risk_fresh.overallScore
    stale_contributor = risk_stale.contributors[0]
    assert "(Stale Data)" in stale_contributor.factor


def test_risk_score_is_strictly_bounded_and_explainable():
    # Massive pile of critical findings
    assets = [make_asset(f"a{i}", f"srv-{i}", "TIER_0_CROWN_JEWEL", is_public=True) for i in range(10)]
    findings = [make_finding(f"v{i}", f"a{i}", "CRITICAL") for i in range(10)]

    risk = calculate_environment_risk("env-test", assets, findings, [])
    # Must be clamped at 100.0
    assert risk.overallScore <= 100.0
    assert len(risk.contributors) > 0
    # Explainability payload present
    assert risk.explanation is not None
    assert risk.explanation["findingsEvaluated"] == 10

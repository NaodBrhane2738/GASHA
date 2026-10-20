"""
==============================================================================
FILE: apps/api/app/risk/calculator.py
ROLE / OWNERSHIP: Cybersecurity & Risk Engineers
OBJECTIVE: Deterministic, explainable mathematical scoring engine for asset & environment risk.
FORMULA:
  Finding Impact = Severity_Base * Asset_Criticality_Mult * Freshness_Factor
  Total Score = Clamp_0_100( Sum(Finding_Impacts) + Attack_Path_Impacts + Exposure_Impacts )
==============================================================================
"""

from typing import List, Dict, Any, Tuple
from app.schemas.asset import AssetResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.schemas.attack_path import AttackPathResponse
from app.schemas.risk import (
    RiskScoreResponse,
    RiskContributorSchema
)

# Deterministic scoring parameters
SEVERITY_WEIGHTS = {
    "CRITICAL": 25.0,
    "HIGH": 15.0,
    "MEDIUM": 8.0,
    "LOW": 3.0
}

CRITICALITY_MULTIPLIERS = {
    "TIER_0_CROWN_JEWEL": 2.0,
    "TIER_1_HIGH": 1.5,
    "TIER_2_MEDIUM": 1.0,
    "TIER_3_LOW": 0.5
}


def calculate_environment_risk(
    environment_id: str,
    assets: List[AssetResponse],
    findings: List[VulnerabilityResponse],
    attack_paths: List[AttackPathResponse],
    active_incidents_count: int = 0
) -> RiskScoreResponse:
    """
    Computes an explainable, deterministic environment risk score between 0.0 and 100.0.
    """
    assets_by_id = {a.id: a for a in assets}
    contributors: List[RiskContributorSchema] = []
    
    total_raw_score = 0.0
    critical_assets_at_risk: set = set()
    high_risk_vuln_count = 0
    active_reachable_paths_count = 0

    # 1. Evaluate Findings
    for f in findings:
        if f.status != "OPEN":
            # Resolved or mitigated findings do not contribute to risk
            continue

        base_weight = SEVERITY_WEIGHTS.get(f.severity, 3.0)
        asset = assets_by_id.get(f.assetId)
        crit_mult = CRITICALITY_MULTIPLIERS.get(asset.criticality, 1.0) if asset else 1.0
        freshness_factor = 0.5 if f.isStale else 1.0

        finding_impact = base_weight * crit_mult * freshness_factor
        total_raw_score += finding_impact

        if f.severity in ("CRITICAL", "HIGH"):
            high_risk_vuln_count += 1
            if asset and asset.criticality in ("TIER_0_CROWN_JEWEL", "TIER_1_HIGH"):
                critical_assets_at_risk.add(asset.id)

        asset_label = asset.name if asset else f.assetId
        stale_note = " (Stale Data)" if f.isStale else ""
        contributors.append(
            RiskContributorSchema(
                factor=f"{f.severity} Vulnerability: {f.title}{stale_note}",
                weight=round(finding_impact, 1),
                description=f"Impacting {asset_label} ({asset.criticality if asset else 'TIER_2'}). Base: {base_weight}, Multiplier: {crit_mult}x"
            )
        )

    # 2. Public Exposure Modifier for assets with weaknesses
    for a in assets:
        if a.isPubliclyExposed:
            # Check if this exposed asset has open findings
            asset_open_findings = [f for f in findings if f.assetId == a.id and f.status == "OPEN"]
            if asset_open_findings:
                exposure_penalty = 8.0 * CRITICALITY_MULTIPLIERS.get(a.criticality, 1.0)
                total_raw_score += exposure_penalty
                contributors.append(
                    RiskContributorSchema(
                        factor=f"Public Exposure of Vulnerable Asset: {a.name}",
                        weight=round(exposure_penalty, 1),
                        description=f"Asset '{a.name}' is publicly reachable while harboring {len(asset_open_findings)} unmitigated findings."
                    )
                )

    # 3. Attack Paths Impact
    for path in attack_paths:
        if path.isActive and path.reachability == "REACHABLE":
            active_reachable_paths_count += 1
            path_weight = round(path.pathScore * 0.25, 1)  # 25% of path score contributes to overall env risk
            total_raw_score += path_weight
            contributors.append(
                RiskContributorSchema(
                    factor=f"Active Attack Path: {path.id}",
                    weight=path_weight,
                    description=f"Reachable traversal route from entrypoint to high-value target with severity {path.severity}."
                )
            )

    # 4. Active Incident Penalty
    if active_incidents_count > 0:
        incident_penalty = min(active_incidents_count * 10.0, 30.0)
        total_raw_score += incident_penalty
        contributors.append(
            RiskContributorSchema(
                factor=f"Active Security Incidents ({active_incidents_count})",
                weight=round(incident_penalty, 1),
                description=f"{active_incidents_count} active correlated incidents currently in progress."
            )
        )

    # Normalization and clamping to 0.0 - 100.0
    final_score = min(max(round(total_raw_score, 1), 0.0), 100.0)

    # Sort contributors by weight descending
    contributors.sort(key=lambda c: c.weight, reverse=True)

    from datetime import datetime, timezone
    return RiskScoreResponse(
        overallScore=final_score,
        criticalAssetsAtRiskCount=len(critical_assets_at_risk),
        highRiskVulnerabilitiesCount=high_risk_vuln_count,
        activeAttackPathsCount=active_reachable_paths_count,
        activeIncidentsCount=active_incidents_count,
        contributors=contributors[:10],  # Top 10 primary contributors
        calculatedAt=datetime.now(timezone.utc).isoformat(),
        environmentId=environment_id,
        explanation={
            "rawScore": total_raw_score,
            "totalContributorsCount": len(contributors),
            "findingsEvaluated": len(findings),
            "assetsEvaluated": len(assets),
            "activePathsEvaluated": len(attack_paths)
        }
    )

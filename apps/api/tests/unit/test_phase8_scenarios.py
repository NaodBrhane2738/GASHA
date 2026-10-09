"""
==============================================================================
FILE: apps/api/tests/unit/test_phase8_scenarios.py
OBJECTIVE: Reproducible end-to-end unit tests for Demonstration Scenarios A, B, C, D, E.
==============================================================================
"""

import time
import pytest
from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.db.repositories.connection_repository import get_connection_repository
from app.db.repositories.attack_path_repository import get_attack_path_repository
from app.db.repositories.risk_repository import get_risk_repository
from app.schemas.asset import AssetBase, RelationshipBase
from app.schemas.connection import ConnectionRecord
from app.workers.recalculation import recalculate_environment_security_state
from app.digital_twin.state import set_asset_containment_state


@pytest.fixture(autouse=True)
def clean_all_repos():
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    get_connection_repository().clear()
    get_attack_path_repository().clear()
    get_risk_repository().clear()
    yield
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    get_connection_repository().clear()
    get_attack_path_repository().clear()
    get_risk_repository().clear()


def test_scenario_a_public_entry_point_with_confirmed_weakness():
    """
    Scenario A:
    Public application with confirmed weakness, connected to Crown Jewel DB.
    Verifies finding generation, risk breakdown, and active attack path discovery.
    """
    asset_repo = get_asset_repository()
    
    # 1. Public web portal with vulnerable dependency in package.json
    portal = asset_repo.upsert_asset(
        AssetBase(
            name="customer-portal",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_1_HIGH",
            environmentId="env-scenario-a",
            source="VERCEL",
            metadata={
                "domains": ["portal.acme.com"],
                "manifests": {
                    "package.json": {
                        "dependencies": ["jsonwebtoken"],
                        "dependencyVersions": {"jsonwebtoken": "8.5.1"}
                    }
                }
            },
            isPubliclyExposed=True
        )
    )

    # 2. Protected backend Crown Jewel DB
    db = asset_repo.upsert_asset(
        AssetBase(
            name="core-db",
            type="DATABASE",
            criticality="TIER_0_CROWN_JEWEL",
            environmentId="env-scenario-a",
            source="STATIC_CONFIG",
            isPubliclyExposed=False
        )
    )

    # 3. Confirmed Relationship: Portal CALLS DB
    asset_repo.upsert_relationship(
        RelationshipBase(
            sourceAssetId=portal.id,
            targetAssetId=db.id,
            type="CALLS",
            metadata={"protocol": "postgresql"}
        ),
        environment_id="env-scenario-a"
    )

    # Execute recalculation pipeline
    start_t = time.perf_counter()
    result = recalculate_environment_security_state("env-scenario-a", trigger_event="SCENARIO_A_EXECUTION")
    duration = time.perf_counter() - start_t

    # Verification:
    # 1. Findings generated: Public exposure (LOW) + Vulnerable Dependency (HIGH)
    vuln_repo = get_vulnerability_repository()
    findings = vuln_repo.list_findings("env-scenario-a", status="OPEN")
    assert len(findings) == 2
    vuln_dep = next(f for f in findings if f.ruleId == "RULE-DEP-VULN-001")
    assert vuln_dep.cveId == "CVE-2022-23529"
    assert vuln_dep.severity == "HIGH"

    # 2. Attack Path discovered: portal -> DB
    path_repo = get_attack_path_repository()
    paths = path_repo.list_attack_paths("env-scenario-a")
    assert len(paths) == 1
    assert paths[0].entryPointAssetId == portal.id
    assert paths[0].targetAssetId == db.id
    assert paths[0].reachability == "REACHABLE"
    assert paths[0].pathScore >= 60.0

    # 3. Risk score explains the risk factors
    risk_repo = get_risk_repository()
    risk = risk_repo.get_current_risk("env-scenario-a")
    assert risk.overallScore > 30.0
    assert any("jsonwebtoken" in c.factor for c in risk.contributors)
    assert any("Attack Path" in c.factor for c in risk.contributors)
    assert duration < 1.0


def test_scenario_b_public_asset_without_confirmed_vulnerability():
    """
    Scenario B:
    Public application with no confirmed weakness in available evidence.
    Verifies that GASHA does NOT invent a critical vulnerability or high-risk attack path.
    """
    asset_repo = get_asset_repository()
    
    # Clean public static site with up-to-date dependencies
    site = asset_repo.upsert_asset(
        AssetBase(
            name="marketing-site",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_2_MEDIUM",
            environmentId="env-scenario-b",
            source="VERCEL",
            metadata={
                "domains": ["www.acme.com"],
                "nodeVersion": "18.x",
                "manifests": {
                    "package.json": {
                        "dependencies": ["react", "next"],
                        "dependencyVersions": {"react": "18.2.0", "next": "14.0.0"}
                    }
                }
            },
            isPubliclyExposed=True
        )
    )

    recalculate_environment_security_state("env-scenario-b", trigger_event="SCENARIO_B_EXECUTION")

    vuln_repo = get_vulnerability_repository()
    findings = vuln_repo.list_findings("env-scenario-b", status="OPEN")
    
    # Exactly 1 informational finding: Public App Exposure (LOW)
    assert len(findings) == 1
    assert findings[0].ruleId == "RULE-EXPOSURE-APP-001"
    assert findings[0].severity == "LOW"

    # NO attack paths created because there is no crown jewel or exploitable weakness
    path_repo = get_attack_path_repository()
    paths = path_repo.list_attack_paths("env-scenario-b")
    assert len(paths) == 0

    # Low risk score
    risk_repo = get_risk_repository()
    risk = risk_repo.get_current_risk("env-scenario-b")
    assert risk.overallScore <= 15.0


def test_scenario_c_incomplete_discovery():
    """
    Scenario C:
    Simulates a connector sync error. Existing valid findings must NOT be resolved.
    """
    asset_repo = get_asset_repository()
    conn_repo = get_connection_repository()

    # Asset with vulnerable dependency
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="acme/api",
            type="GITHUB_REPOSITORY",
            criticality="TIER_1_HIGH",
            environmentId="env-scenario-c",
            source="GITHUB",
            metadata={
                "manifests": {
                    "requirements.txt": {
                        "dependencies": ["requests"],
                        "dependencyVersions": {"requests": "2.25.0"}
                    }
                }
            }
        )
    )

    # First baseline assessment
    recalculate_environment_security_state("env-scenario-c")
    vuln_repo = get_vulnerability_repository()
    findings = vuln_repo.list_findings("env-scenario-c", status="OPEN")
    assert len(findings) == 1
    vuln_id = findings[0].id

    # Simulate GitHub sync failure (recorded in connection repo as ERROR)
    conn_repo.save_connection(
        ConnectionRecord(
            id="conn-gh-c",
            provider="GITHUB",
            environmentId="env-scenario-c",
            encryptedToken="enc",
            status="ERROR",
            errorMessage="GitHub upstream 503 Service Unavailable",
            createdAt="2026-10-09T00:00:00Z",
            updatedAt="2026-10-09T00:00:00Z"
        )
    )

    # Incomplete discovery clears metadata
    asset.metadata["manifests"] = {}
    asset_repo.upsert_asset(asset, asset_id=asset.id)

    # Run recalculation during provider error
    recalculate_environment_security_state("env-scenario-c")

    # Finding MUST remain OPEN and not falsely resolved
    preserved_finding = vuln_repo.get_finding(vuln_id, "env-scenario-c")
    assert preserved_finding.status == "OPEN"


def test_scenario_d_response_changes_reachability():
    """
    Scenario D:
    Active defense response isolates the entrypoint asset.
    The attack path reachability changes to BLOCKED without falsely resolving the underlying vulnerability.
    """
    asset_repo = get_asset_repository()
    
    entry = asset_repo.upsert_asset(
        AssetBase(
            name="api-gateway",
            type="SERVICE",
            criticality="TIER_1_HIGH",
            environmentId="env-scenario-d",
            source="VERCEL",
            metadata={
                "domains": ["api.acme.com"],
                "manifests": {
                    "package.json": {
                        "dependencies": ["lodash"],
                        "dependencyVersions": {"lodash": "4.17.20"}
                    }
                }
            },
            isPubliclyExposed=True
        )
    )
    crown = asset_repo.upsert_asset(
        AssetBase(
            name="vault",
            type="SECRET_STORE",
            criticality="TIER_0_CROWN_JEWEL",
            environmentId="env-scenario-d",
            source="STATIC_CONFIG",
            isPubliclyExposed=False
        )
    )
    asset_repo.upsert_relationship(
        RelationshipBase(sourceAssetId=entry.id, targetAssetId=crown.id, type="CALLS"),
        environment_id="env-scenario-d"
    )

    # Initial recalculation
    recalculate_environment_security_state("env-scenario-d")
    path_repo = get_attack_path_repository()
    paths_before = path_repo.list_attack_paths("env-scenario-d")
    assert len(paths_before) == 1
    assert paths_before[0].reachability == "REACHABLE"
    risk_before = get_risk_repository().get_current_risk("env-scenario-d").overallScore

    # ACTIVE RESPONSE: Operator approves containment, isolating entrypoint
    set_asset_containment_state("env-scenario-d", entry.id, "ISOLATED")

    # Recalculate security state
    recalculate_environment_security_state("env-scenario-d", trigger_event="CONTAINMENT_APPLIED")

    # Post-containment verification:
    # 1. Attack path is blocked/removed from active traversals
    active_paths_after = path_repo.list_attack_paths("env-scenario-d", is_active=True)
    assert len(active_paths_after) == 0

    # 2. Environment risk decreases as threat path is contained
    risk_after = get_risk_repository().get_current_risk("env-scenario-d").overallScore
    assert risk_after < risk_before

    # 3. CRITICAL INVARIANT: Underlying vulnerability in code is NOT marked resolved!
    vuln_repo = get_vulnerability_repository()
    findings = vuln_repo.list_findings("env-scenario-d")
    vuln = next(f for f in findings if f.ruleId == "RULE-DEP-VULN-001")
    assert vuln.status == "OPEN", "Containing an asset must not falsely mark code vulnerability fixed"


def test_scenario_e_tenant_isolation():
    """
    Scenario E:
    Distinct synthetic environments with overlapping names maintain strict data isolation.
    """
    asset_repo = get_asset_repository()

    # Tenant 1: Insecure environment
    t1_app = asset_repo.upsert_asset(
        AssetBase(
            name="web-app",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_1_HIGH",
            environmentId="tenant-alpha",
            source="VERCEL",
            metadata={"domains": ["alpha.com"], "branchProtectionStatus": "NOT_ENABLED"},
            isPubliclyExposed=True
        )
    )

    # Tenant 2: Clean environment
    t2_app = asset_repo.upsert_asset(
        AssetBase(
            name="web-app",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_1_HIGH",
            environmentId="tenant-beta",
            source="VERCEL",
            metadata={"domains": ["beta.com"]},
            isPubliclyExposed=False
        )
    )

    recalculate_environment_security_state("tenant-alpha")
    recalculate_environment_security_state("tenant-beta")

    vuln_repo = get_vulnerability_repository()
    risk_repo = get_risk_repository()

    alpha_findings = vuln_repo.list_findings("tenant-alpha")
    beta_findings = vuln_repo.list_findings("tenant-beta")
    assert len(alpha_findings) > 0
    assert len(beta_findings) == 0

    alpha_risk = risk_repo.get_current_risk("tenant-alpha").overallScore
    beta_risk = risk_repo.get_current_risk("tenant-beta").overallScore
    assert alpha_risk > beta_risk
    assert beta_risk == 0.0

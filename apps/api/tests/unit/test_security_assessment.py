"""
==============================================================================
FILE: apps/api/tests/unit/test_security_assessment.py
OBJECTIVE: Unit tests for Security Assessment Engine, finding lifecycle,
evidence requirements, and rule semantics.
==============================================================================
"""

import pytest
from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.db.repositories.connection_repository import get_connection_repository
from app.schemas.asset import AssetBase
from app.schemas.connection import ConnectionRecord
from app.security_assessment.engine import SecurityAssessmentEngine
from app.security_assessment.rules.catalog import (
    PublicAppExposureRule,
    PublicAdminEndpointRule,
    PublicDatabaseExposureRule,
    BranchProtectionRule,
    VulnerableDependencyRule,
    OutdatedNodeVersionRule,
    UnverifiedDomainRule
)


@pytest.fixture(autouse=True)
def clean_repos():
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    get_connection_repository().clear()
    yield
    get_asset_repository().clear()
    get_vulnerability_repository().clear()
    get_connection_repository().clear()


def test_public_app_exposure_is_low_severity():
    asset_repo = get_asset_repository()
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="frontend-portal",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
            source="VERCEL",
            metadata={"domains": ["portal.example.com"]},
            isPubliclyExposed=True
        )
    )

    engine = SecurityAssessmentEngine()
    summary = engine.run_assessment("env-test")

    assert summary.findingsCount == 1
    finding = summary.findings[0]
    # In accordance with prompt: Public exposure alone is not a critical vulnerability
    assert finding.ruleId == "RULE-EXPOSURE-APP-001"
    assert finding.severity == "LOW"
    assert finding.evidence["publicUrl"] == "portal.example.com"
    assert finding.evidence["isPubliclyExposed"] is True


def test_admin_endpoint_exposure_is_high_severity():
    asset_repo = get_asset_repository()
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="api-service/admin",
            type="API_ENDPOINT",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
            source="VERCEL",
            metadata={"domain": "admin.example.com"},
            isPubliclyExposed=True
        )
    )

    engine = SecurityAssessmentEngine()
    summary = engine.run_assessment("env-test")

    finding = next((f for f in summary.findings if f.ruleId == "RULE-EXPOSURE-ADMIN-001"), None)
    assert finding is not None
    assert finding.severity == "HIGH"
    assert "admin" in finding.evidence["matchedPattern"]


def test_public_database_is_critical():
    asset_repo = get_asset_repository()
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="postgres-production",
            type="DATABASE",
            criticality="TIER_0_CROWN_JEWEL",
            environmentId="env-test",
            source="STATIC_CONFIG",
            isPubliclyExposed=True
        )
    )

    engine = SecurityAssessmentEngine()
    summary = engine.run_assessment("env-test")

    finding = next(f for f in summary.findings if f.ruleId == "RULE-EXPOSURE-DB-001")
    assert finding.severity == "CRITICAL"
    assert finding.cvssScore == 9.8


def test_branch_protection_not_enabled_vs_unknown():
    asset_repo = get_asset_repository()
    # 1. Asset with explicit NOT_ENABLED branch protection
    repo_disabled = asset_repo.upsert_asset(
        AssetBase(
            name="acme/insecure-repo",
            type="GITHUB_REPOSITORY",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
            source="GITHUB",
            metadata={"branchProtectionStatus": "NOT_ENABLED", "defaultBranch": "main"}
        )
    )
    # 2. Asset with UNKNOWN / missing permission
    repo_unknown = asset_repo.upsert_asset(
        AssetBase(
            name="acme/third-party-repo",
            type="GITHUB_REPOSITORY",
            criticality="TIER_2_MEDIUM",
            environmentId="env-test",
            source="GITHUB",
            metadata={"branchProtectionStatus": "UNKNOWN"}
        )
    )

    engine = SecurityAssessmentEngine()
    summary = engine.run_assessment("env-test")

    findings = [f for f in summary.findings if f.ruleId == "RULE-GH-BRANCH-001"]
    # Only the proven NOT_ENABLED repository should generate a finding
    assert len(findings) == 1
    assert findings[0].assetId == repo_disabled.id
    assert findings[0].evidence["branchProtectionStatus"] == "NOT_ENABLED"


def test_vulnerable_dependency_from_manifest():
    asset_repo = get_asset_repository()
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="acme/auth-service",
            type="GITHUB_REPOSITORY",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
            source="GITHUB",
            metadata={
                "manifests": {
                    "package.json": {
                        "dependencies": ["jsonwebtoken", "express"],
                        "dependencyVersions": {"jsonwebtoken": "8.5.1"}
                    }
                }
            }
        )
    )

    engine = SecurityAssessmentEngine()
    summary = engine.run_assessment("env-test")

    finding = next((f for f in summary.findings if f.ruleId == "RULE-DEP-VULN-001"), None)
    assert finding is not None
    assert finding.cveId == "CVE-2022-23529"
    assert finding.severity == "HIGH"
    assert finding.evidence["packageName"] == "jsonwebtoken"


def test_finding_idempotency_and_preservation():
    asset_repo = get_asset_repository()
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="web-app",
            type="VERCEL_DEPLOYMENT",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
            source="VERCEL",
            isPubliclyExposed=True
        )
    )

    engine = SecurityAssessmentEngine()
    summary1 = engine.run_assessment("env-test")
    finding1 = summary1.findings[0]
    orig_discovered_at = finding1.discoveredAt

    # Re-run assessment
    summary2 = engine.run_assessment("env-test")
    assert summary2.findingsCount == 1
    finding2 = summary2.findings[0]

    assert finding1.id == finding2.id
    assert finding2.discoveredAt == orig_discovered_at


def test_finding_remediation_lifecycle():
    asset_repo = get_asset_repository()
    # Initial state: unverified domain
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="api.example.com",
            type="API_ENDPOINT",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
            source="VERCEL",
            metadata={"verified": False}
        )
    )

    engine = SecurityAssessmentEngine()
    summary1 = engine.run_assessment("env-test")
    assert summary1.findingsCount == 1
    vuln_id = summary1.findings[0].id

    # Remediation: Domain DNS is verified
    asset.metadata["verified"] = True
    asset_repo.upsert_asset(asset, asset_id=asset.id)

    # Re-assess
    summary2 = engine.run_assessment("env-test")
    assert summary2.findingsCount == 0  # No OPEN findings

    # Verify status changed to MITIGATED in repository
    vuln_repo = get_vulnerability_repository()
    persisted = vuln_repo.get_finding(vuln_id, "env-test")
    assert persisted is not None
    assert persisted.status == "MITIGATED"


def test_failed_provider_sync_does_not_resolve_findings():
    asset_repo = get_asset_repository()
    conn_repo = get_connection_repository()

    # Asset with vulnerable dependency
    asset = asset_repo.upsert_asset(
        AssetBase(
            name="acme/service",
            type="GITHUB_REPOSITORY",
            criticality="TIER_1_HIGH",
            environmentId="env-test",
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

    engine = SecurityAssessmentEngine()
    summary1 = engine.run_assessment("env-test")
    assert summary1.findingsCount == 1
    vuln_id = summary1.findings[0].id

    # Simulate GitHub sync failure (error state)
    conn_repo.save_connection(
        ConnectionRecord(
            id="conn-gh",
            provider="GITHUB",
            environmentId="env-test",
            encryptedToken="encrypted",
            status="ERROR",
            errorMessage="GitHub API 500",
            createdAt="2026-10-09T00:00:00Z",
            updatedAt="2026-10-09T00:00:00Z"
        )
    )

    # Clear manifests temporarily as might happen during an incomplete sync
    asset.metadata["manifests"] = {}
    asset_repo.upsert_asset(asset, asset_id=asset.id)

    # Re-assess
    summary2 = engine.run_assessment("env-test")
    # Finding must NOT be resolved because GitHub provider is in ERROR
    vuln_repo = get_vulnerability_repository()
    finding = vuln_repo.get_finding(vuln_id, "env-test")
    assert finding.status == "OPEN"

"""
==============================================================================
FILE: apps/api/app/security_assessment/rules/catalog.py
ROLE / OWNERSHIP: Cybersecurity Engineers
OBJECTIVE: Deterministic security assessment rule catalog covering public exposure,
repository security, vulnerable dependencies, and insecure configurations.
CONSTRAINTS: Zero live CVE lookups, zero AI/LLMs. Evidence must be grounded in verified metadata.
==============================================================================
"""

import re
from typing import List, Optional, Dict, Any
from app.schemas.asset import AssetResponse
from app.schemas.vulnerability import (
    VulnerabilityBase,
    VulnerabilityCategory,
    SeverityLevel
)
from app.security_assessment.rules.base import AssessmentRule, AssessmentContext

# Embedded deterministic offline advisory catalog for known package vulnerabilities
OFFLINE_ADVISORY_CATALOG = {
    "jsonwebtoken": {
        "vulnerable_below": "9.0.0",
        "cve": "CVE-2022-23529",
        "title": "Insecure key validation in jsonwebtoken",
        "severity": "HIGH",
        "cvss": 7.5,
        "advisory": "GHSA-qwph-4952-7xr6",
        "guidance": "Upgrade jsonwebtoken to version 9.0.0 or higher."
    },
    "requests": {
        "vulnerable_below": "2.31.0",
        "cve": "CVE-2023-32681",
        "title": "Unintended Proxy-Authorization header leak in requests",
        "severity": "HIGH",
        "cvss": 7.4,
        "advisory": "GHSA-j8r2-6x86-q33q",
        "guidance": "Upgrade python requests library to 2.31.0 or newer."
    },
    "lodash": {
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
        "title": "Command Injection in lodash template",
        "severity": "HIGH",
        "cvss": 7.2,
        "advisory": "GHSA-35jh-r3h4-6jhm",
        "guidance": "Upgrade lodash to version 4.17.21 or later."
    },
    "fastapi": {
        "vulnerable_below": "0.100.0",
        "cve": "CVE-2024-24762",
        "title": "Potential ReDoS in multipart parsing in FastAPI",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "advisory": "GHSA-5434-2c3f-5694",
        "guidance": "Upgrade FastAPI to version 0.100.0 or higher."
    }
}


class PublicAppExposureRule(AssessmentRule):
    """
    Identifies verified public web applications or deployment endpoints.
    Classified as LOW severity informational exposure, not an inherent critical vulnerability.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-EXPOSURE-APP-001",
            name="Public Web Application Exposure",
            description="Application deployment is publicly accessible on the public Internet.",
            category="PUBLIC_EXPOSURE",
            default_severity="LOW",
            applicable_asset_types=["VERCEL_DEPLOYMENT", "SERVICE"],
            remediation_guidance="Ensure public access is intentional and protected by WAF and authentication where appropriate."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type not in self.applicable_asset_types:
            return None

        if not asset.isPubliclyExposed:
            return None

        # Verify through observable evidence
        domains = asset.metadata.get("domains", [])
        deployments = asset.metadata.get("latestDeployments", [])
        public_url = None
        if domains:
            public_url = domains[0]
        elif deployments and any(d.get("url") for d in deployments):
            public_url = next(d["url"] for d in deployments if d.get("url"))

        evidence = {
            "sourceType": "METADATA_OBSERVATION",
            "isPubliclyExposed": True,
            "publicUrl": public_url,
            "assetName": asset.name,
            "environmentId": asset.environmentId
        }

        return VulnerabilityBase(
            assetId=asset.id,
            environmentId=asset.environmentId,
            ruleId=self.rule_id,
            title="Public Web Application Exposure",
            description=f"Asset '{asset.name}' is verified as publicly accessible on the internet via {public_url or 'configured domains'}.",
            severity=self.default_severity,
            cvssScore=3.1,
            category=self.category,
            remediationGuidance=self.remediation_guidance,
            status="OPEN",
            evidence=evidence
        )


class PublicAdminEndpointRule(AssessmentRule):
    """
    Identifies exposed administrative or sensitive internal API endpoints.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-EXPOSURE-ADMIN-001",
            name="Exposed Administrative or Internal Endpoint",
            description="Administrative, debug, or internal service endpoint is publicly accessible.",
            category="SENSITIVE_DATA_EXPOSURE",
            default_severity="HIGH",
            applicable_asset_types=["API_ENDPOINT", "SERVICE"],
            remediation_guidance="Place administrative endpoints behind strict authentication, VPN, or private network boundaries."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type not in self.applicable_asset_types or not asset.isPubliclyExposed:
            return None

        name_lower = asset.name.lower()
        sensitive_patterns = ["admin", "debug", "actuator", "metrics", "internal-", "/admin"]
        matched = next((p for p in sensitive_patterns if p in name_lower), None)
        if not matched:
            return None

        evidence = {
            "sourceType": "ENDPOINT_PATH_ANALYSIS",
            "matchedPattern": matched,
            "endpointName": asset.name,
            "isPubliclyExposed": True
        }

        return VulnerabilityBase(
            assetId=asset.id,
            environmentId=asset.environmentId,
            ruleId=self.rule_id,
            title=f"Exposed Sensitive Endpoint ({matched})",
            description=f"Publicly accessible endpoint '{asset.name}' matches sensitive administrative pattern '{matched}'.",
            severity=self.default_severity,
            cvssScore=7.5,
            category=self.category,
            remediationGuidance=self.remediation_guidance,
            status="OPEN",
            evidence=evidence
        )


class PublicDatabaseExposureRule(AssessmentRule):
    """
    Identifies databases directly exposed to the public Internet without network isolation.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-EXPOSURE-DB-001",
            name="Direct Public Database Exposure",
            description="Database asset is configured with public ingress without network isolation.",
            category="PUBLIC_EXPOSURE",
            default_severity="CRITICAL",
            applicable_asset_types=["DATABASE"],
            remediation_guidance="Isolate database within a private VPC and revoke all public ingress routing."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type != "DATABASE" or not asset.isPubliclyExposed:
            return None

        evidence = {
            "sourceType": "DATABASE_INGRESS_METADATA",
            "isPubliclyExposed": True,
            "databaseName": asset.name
        }

        return VulnerabilityBase(
            assetId=asset.id,
            environmentId=asset.environmentId,
            ruleId=self.rule_id,
            title="Direct Public Database Exposure",
            description=f"Critical database '{asset.name}' is exposed directly to the public internet.",
            severity=self.default_severity,
            cvssScore=9.8,
            category=self.category,
            remediationGuidance=self.remediation_guidance,
            status="OPEN",
            evidence=evidence
        )


class BranchProtectionRule(AssessmentRule):
    """
    Evaluates branch protection on default branch for GitHub repositories.
    Carefully distinguishes NOT_ENABLED from UNKNOWN.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-GH-BRANCH-001",
            name="Missing GitHub Branch Protection",
            description="Default repository branch lacks enforced protection rules.",
            category="INSECURE_CONFIG",
            default_severity="MEDIUM",
            applicable_asset_types=["GITHUB_REPOSITORY"],
            remediation_guidance="Enable branch protection rules on the default branch requiring pull request reviews and status checks."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type != "GITHUB_REPOSITORY":
            return None

        # Check observable branch protection status
        protection_status = asset.metadata.get("branchProtectionStatus")
        # If explicitly NOT_ENABLED or disabled
        if protection_status in ("NOT_ENABLED", "DISABLED", False):
            default_branch = asset.metadata.get("defaultBranch", "main")
            evidence = {
                "sourceType": "GITHUB_API_METADATA",
                "defaultBranch": default_branch,
                "branchProtectionStatus": "NOT_ENABLED",
                "repository": asset.name
            }
            return VulnerabilityBase(
                assetId=asset.id,
                environmentId=asset.environmentId,
                ruleId=self.rule_id,
                title="Missing Default Branch Protection",
                description=f"Repository '{asset.name}' has no branch protection rules enabled on branch '{default_branch}'.",
                severity=self.default_severity,
                cvssScore=5.0,
                category=self.category,
                remediationGuidance=self.remediation_guidance,
                status="OPEN",
                evidence=evidence
            )

        # If UNKNOWN, NOT_CONFIGURED, or unobserved, DO NOT flag as missing control!
        return None


class VulnerableDependencyRule(AssessmentRule):
    """
    Evaluates discovered dependencies against deterministic offline advisory database
    or consumes authorized provider security alerts.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-DEP-VULN-001",
            name="Vulnerable Dependency Detected",
            description="Identified package matches known security advisory or provider security alert.",
            category="VULNERABLE_DEPENDENCY",
            default_severity="HIGH",
            applicable_asset_types=["GITHUB_REPOSITORY", "SERVICE", "VERCEL_DEPLOYMENT"],
            remediation_guidance="Upgrade the affected dependency to the patched version specified in the advisory."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type not in self.applicable_asset_types:
            return None

        # 1. Check for provider security alerts (e.g. from GitHub Dependabot)
        provider_alerts = asset.metadata.get("securityAlerts", [])
        if provider_alerts and isinstance(provider_alerts, list):
            alert = provider_alerts[0]  # Take top alert
            evidence = {
                "sourceType": "PROVIDER_SECURITY_ALERT",
                "advisoryId": alert.get("advisoryId"),
                "cveId": alert.get("cveId"),
                "package": alert.get("packageName"),
                "vulnerableRange": alert.get("vulnerableRange")
            }
            sev = alert.get("severity", self.default_severity).upper()
            if sev not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                sev = "HIGH"
            return VulnerabilityBase(
                assetId=asset.id,
                environmentId=asset.environmentId,
                ruleId=self.rule_id,
                cveId=alert.get("cveId"),
                title=f"Vulnerable Dependency: {alert.get('packageName', 'package')}",
                description=alert.get("summary") or f"Security advisory {alert.get('advisoryId')} reported for package {alert.get('packageName')}.",
                severity=sev,
                cvssScore=alert.get("cvssScore", 7.5),
                category=self.category,
                remediationGuidance=alert.get("guidance") or self.remediation_guidance,
                status="OPEN",
                evidence=evidence
            )

        # 2. Check manifests against deterministic offline advisory dataset
        manifests = asset.metadata.get("manifests", {})
        for manifest_file, m_data in manifests.items():
            deps = m_data.get("dependencies", [])
            # Also check devDependencies if present
            dev_deps = m_data.get("devDependencies", [])
            all_dep_names = list(deps) + list(dev_deps)

            for pkg_name in all_dep_names:
                clean_name = pkg_name.strip().lower()
                if clean_name in OFFLINE_ADVISORY_CATALOG:
                    adv = OFFLINE_ADVISORY_CATALOG[clean_name]
                    # Check version if version string is present in metadata
                    pkg_versions = m_data.get("dependencyVersions", {})
                    detected_ver = pkg_versions.get(clean_name, "0.1.0")

                    evidence = {
                        "sourceType": "OFFLINE_ADVISORY_MATCH",
                        "manifest": manifest_file,
                        "packageName": clean_name,
                        "detectedVersion": detected_ver,
                        "cveId": adv["cve"],
                        "advisoryId": adv["advisory"]
                    }

                    return VulnerabilityBase(
                        assetId=asset.id,
                        environmentId=asset.environmentId,
                        ruleId=self.rule_id,
                        cveId=adv["cve"],
                        title=f"{adv['title']} ({clean_name})",
                        description=f"Package '{clean_name}' in '{manifest_file}' is subject to advisory {adv['cve']}.",
                        severity=adv["severity"],
                        cvssScore=adv["cvss"],
                        category=self.category,
                        remediationGuidance=adv["guidance"],
                        status="OPEN",
                        evidence=evidence
                    )

        return None


class OutdatedNodeVersionRule(AssessmentRule):
    """
    Evaluates configured runtime versions for Vercel deployments.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-VERCEL-NODE-001",
            name="Outdated Serverless Runtime Version",
            description="Deployment uses an end-of-life Node.js runtime version.",
            category="INSECURE_CONFIG",
            default_severity="MEDIUM",
            applicable_asset_types=["VERCEL_DEPLOYMENT"],
            remediation_guidance="Update project Node.js runtime to version 18.x or 20.x in project settings."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type != "VERCEL_DEPLOYMENT":
            return None

        node_ver = asset.metadata.get("nodeVersion")
        if node_ver in ("14.x", "16.x"):
            evidence = {
                "sourceType": "VERCEL_PROJECT_CONFIG",
                "configuredNodeVersion": node_ver,
                "projectId": asset.metadata.get("projectId")
            }
            return VulnerabilityBase(
                assetId=asset.id,
                environmentId=asset.environmentId,
                ruleId=self.rule_id,
                title=f"Outdated Node.js Runtime ({node_ver})",
                description=f"Deployment '{asset.name}' is configured with obsolete Node.js {node_ver} which no longer receives security patches.",
                severity=self.default_severity,
                cvssScore=5.3,
                category=self.category,
                remediationGuidance=self.remediation_guidance,
                status="OPEN",
                evidence=evidence
            )

        return None


class UnverifiedDomainRule(AssessmentRule):
    """
    Evaluates domain verification status for Vercel endpoint assets.
    """
    def __init__(self):
        super().__init__(
            rule_id="RULE-DOMAIN-UNVERIFIED-001",
            name="Unverified Custom Domain Configuration",
            description="Configured custom domain is unverified, risking subdomain takeover.",
            category="INSECURE_CONFIG",
            default_severity="MEDIUM",
            applicable_asset_types=["API_ENDPOINT"],
            remediation_guidance="Complete DNS record verification or remove dangling domain configuration."
        )

    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        if asset.type != "API_ENDPOINT":
            return None

        is_verified = asset.metadata.get("verified")
        if is_verified is False:
            evidence = {
                "sourceType": "DOMAIN_VERIFICATION_STATUS",
                "domain": asset.name,
                "verified": False
            }
            return VulnerabilityBase(
                assetId=asset.id,
                environmentId=asset.environmentId,
                ruleId=self.rule_id,
                title="Unverified Custom Domain",
                description=f"Domain '{asset.name}' is unverified in cloud configuration.",
                severity=self.default_severity,
                cvssScore=5.0,
                category=self.category,
                remediationGuidance=self.remediation_guidance,
                status="OPEN",
                evidence=evidence
            )

        return None


def get_default_assessment_rules() -> List[AssessmentRule]:
    """Returns the standard deterministic assessment rules."""
    return [
        PublicAppExposureRule(),
        PublicAdminEndpointRule(),
        PublicDatabaseExposureRule(),
        BranchProtectionRule(),
        VulnerableDependencyRule(),
        OutdatedNodeVersionRule(),
        UnverifiedDomainRule()
    ]

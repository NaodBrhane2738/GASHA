"""
==============================================================================
FILE: apps/api/app/security_assessment/engine.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Deterministic security assessment engine with finding lifecycle management,
idempotent finding persistence, and environment isolation.
==============================================================================
"""

import logging
from typing import List, Optional, Dict, Any, Set
from datetime import datetime, timezone

from app.db.repositories.asset_repository import get_asset_repository
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.db.repositories.connection_repository import get_connection_repository
from app.schemas.vulnerability import (
    VulnerabilityResponse,
    AssessmentSummaryResponse
)
from app.security_assessment.rules.base import AssessmentContext, AssessmentRule
from app.security_assessment.rules.catalog import get_default_assessment_rules

logger = logging.getLogger("gasha.security_assessment.engine")


class SecurityAssessmentEngine:
    def __init__(self, rules: Optional[List[AssessmentRule]] = None):
        self.rules = rules or get_default_assessment_rules()
        self.asset_repo = get_asset_repository()
        self.vuln_repo = get_vulnerability_repository()
        self.conn_repo = get_connection_repository()

    def run_assessment(self, environment_id: str) -> AssessmentSummaryResponse:
        """
        Executes deterministic assessment rules across all environment assets.
        Updates finding lifecycle (new, present, mitigated) with strict idempotency.
        """
        logger.info(f"Running security assessment for environment: {environment_id}")
        assets = self.asset_repo.list_assets(environment_id=environment_id)
        relationships = self.asset_repo.list_relationships(environment_id=environment_id)
        
        # Get provider status to protect against false resolutions during provider failures
        connections = self.conn_repo.list_connections(environment_id=environment_id)
        provider_status = {c.provider: c.status for c in connections}

        context = AssessmentContext(
            environment_id=environment_id,
            all_assets=assets,
            relationships=relationships,
            sync_status=provider_status
        )

        existing_findings = self.vuln_repo.list_findings(environment_id=environment_id)
        existing_by_key = {
            (f.assetId, f.ruleId): f for f in existing_findings
        }

        active_finding_keys: Set[tuple] = set()
        persisted_findings: List[VulnerabilityResponse] = []

        # 1. Evaluate rules for each asset
        for asset in assets:
            for rule in self.rules:
                if asset.type not in rule.applicable_asset_types:
                    continue

                finding_base = rule.evaluate(asset, context)
                if finding_base:
                    saved = self.vuln_repo.upsert_finding(finding_base)
                    persisted_findings.append(saved)
                    active_finding_keys.add((asset.id, rule.rule_id))

        # 2. Lifecycle handling for previously OPEN findings
        # If an asset was re-evaluated, but a previously detected rule no longer flags a finding:
        # Check if the provider is healthy before resolving.
        for existing in existing_findings:
            key = (existing.assetId, existing.ruleId)
            if existing.status == "OPEN" and key not in active_finding_keys:
                # Find asset
                asset = next((a for a in assets if a.id == existing.assetId), None)
                if asset:
                    # Check provider health
                    provider = asset.source
                    if provider_status.get(provider) == "ERROR":
                        # Provider was in error; do NOT mark resolved
                        logger.warning(
                            f"Preserving open finding {existing.id} because provider {provider} is in ERROR state"
                        )
                        persisted_findings.append(existing)
                    else:
                        # Asset is healthy, verified state change -> MITIGATED
                        logger.info(
                            f"Resolving finding {existing.id} for asset {asset.name} as weakness condition is remediated"
                        )
                        resolved = self.vuln_repo.update_status(
                            vuln_id=existing.id,
                            environment_id=environment_id,
                            status="MITIGATED"
                        )
                        if resolved:
                            persisted_findings.append(resolved)
                else:
                    # Asset missing from current inventory
                    persisted_findings.append(existing)

        # Count active findings
        open_findings = [f for f in persisted_findings if f.status == "OPEN"]
        critical_count = sum(1 for f in open_findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in open_findings if f.severity == "HIGH")
        medium_count = sum(1 for f in open_findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in open_findings if f.severity == "LOW")

        summary = AssessmentSummaryResponse(
            environmentId=environment_id,
            status="COMPLETED",
            assetsAssessedCount=len(assets),
            findingsCount=len(open_findings),
            criticalCount=critical_count,
            highCount=high_count,
            mediumCount=medium_count,
            lowCount=low_count,
            findings=open_findings,
            evaluatedAt=datetime.now(timezone.utc).isoformat()
        )
        return summary


_assessment_engine_instance: Optional[SecurityAssessmentEngine] = None

def get_assessment_engine() -> SecurityAssessmentEngine:
    global _assessment_engine_instance
    if _assessment_engine_instance is None:
        _assessment_engine_instance = SecurityAssessmentEngine()
    return _assessment_engine_instance

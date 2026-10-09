"""
==============================================================================
FILE: apps/api/app/security_assessment/rules/base.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Base interface and context for deterministic security assessment rules.
==============================================================================
"""

from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod

from app.schemas.asset import AssetResponse, AssetType
from app.schemas.vulnerability import (
    VulnerabilityBase,
    VulnerabilityCategory,
    SeverityLevel
)


class AssessmentContext:
    def __init__(
        self,
        environment_id: str,
        all_assets: List[AssetResponse],
        relationships: Optional[List[Any]] = None,
        sync_status: Optional[Dict[str, str]] = None
    ):
        self.environment_id = environment_id
        self.all_assets = {a.id: a for a in all_assets}
        self.assets_by_name = {a.name: a for a in all_assets}
        self.relationships = relationships or []
        self.sync_status = sync_status or {}


class AssessmentRule(ABC):
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        category: VulnerabilityCategory,
        default_severity: SeverityLevel,
        applicable_asset_types: List[AssetType],
        remediation_guidance: str
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.category = category
        self.default_severity = default_severity
        self.applicable_asset_types = applicable_asset_types
        self.remediation_guidance = remediation_guidance

    @abstractmethod
    def evaluate(self, asset: AssetResponse, context: AssessmentContext) -> Optional[VulnerabilityBase]:
        """
        Deterministically evaluates an asset.
        Returns a VulnerabilityBase finding if a weakness is proven by verified evidence, else None.
        """
        pass

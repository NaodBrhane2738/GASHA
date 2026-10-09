"""
==============================================================================
FILE: apps/api/app/schemas/risk.py
ROLE / OWNERSHIP: Backend Engineers & Security Analysts
OBJECTIVE: Pydantic schemas for quantitative Risk scoring, breakdowns, and history.
TOOLS & LIBRARIES: Pydantic v2
CONTRACT COMPLIANCE: Conforms strictly to @gasha/contracts (RiskScore).
==============================================================================
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RiskContributorSchema(BaseModel):
    factor: str
    weight: float
    description: str


class RiskScoreResponse(BaseModel):
    overallScore: float  # 0.0 - 100.0
    criticalAssetsAtRiskCount: int = 0
    highRiskVulnerabilitiesCount: int = 0
    activeAttackPathsCount: int = 0
    contributors: List[RiskContributorSchema] = Field(default_factory=list)
    calculatedAt: str
    environmentId: str = "env-prod"
    explanation: Optional[Dict[str, Any]] = None


class RiskHistoryEntryResponse(BaseModel):
    timestamp: str
    score: float
    triggerEvent: str
    environmentId: str = "env-prod"

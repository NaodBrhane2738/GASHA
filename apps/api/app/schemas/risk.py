"""
==============================================================================
FILE: apps/api/app/schemas/risk.py
ROLE / OWNERSHIP: Backend Engineers & Security Analysts
OBJECTIVE: Pydantic schemas for quantitative Risk scoring, breakdowns, and history.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - RiskContributorSchema: Individual risk factor weighting and description.
  - RiskScoreResponse: Current 0-100 environment risk score.
  - RiskHistoryEntryResponse: Historical progression entry.
EXPECTED RESULTS / BEHAVIOR:
  - Powers the /frontend/risk dial, contributor breakdown, and time-series chart.
==============================================================================
"""

from typing import List
from pydantic import BaseModel

class RiskContributorSchema(BaseModel):
    factor: str
    weight: float
    description: str

class RiskScoreResponse(BaseModel):
    overallScore: float # 0 - 100
    criticalAssetsAtRiskCount: int
    highRiskVulnerabilitiesCount: int
    activeAttackPathsCount: int
    contributors: List[RiskContributorSchema]
    calculatedAt: str

class RiskHistoryEntryResponse(BaseModel):
    timestamp: str
    score: float
    triggerEvent: str

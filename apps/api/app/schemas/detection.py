"""
==============================================================================
FILE: apps/api/app/schemas/detection.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Pydantic schemas for detection events and rule evaluation matches.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - DetectionRuleSummarySchema: Summary of fired rule.
  - DetectionEventResponse: Model for triggered detection events with evidence citations.
EXPECTED RESULTS / BEHAVIOR:
  - Strict typing of detection engine outputs.
==============================================================================
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel

SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

class DetectionRuleSummarySchema(BaseModel):
    ruleId: str
    name: str
    description: str
    severity: SeverityLevel
    confidence: float

class DetectionEventResponse(BaseModel):
    id: str
    rule: DetectionRuleSummarySchema
    matchedEventIds: List[str]
    primaryAssetId: str
    timestamp: str
    severity: SeverityLevel
    confidence: float
    evidenceSummary: str
    metadata: Dict[str, Any] = {}

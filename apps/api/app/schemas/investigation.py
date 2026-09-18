"""
==============================================================================
FILE: apps/api/app/schemas/investigation.py
ROLE / OWNERSHIP: AI Engineers & Backend Engineers
OBJECTIVE: Pydantic schemas for structured Evidence, Attack Stories, and Investigation Results.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - EvidenceSchema: Structured forensic evidence object.
  - RecommendationSchema: AI proposed allowlisted mitigation action.
  - AttackStorySchema: Delineated observed facts, reasonable inferences, and unknowns.
  - InvestigationResultResponse: Final aggregated investigation response payload.
EXPECTED RESULTS / BEHAVIOR:
  - Validates that AI output strictly conforms to grounded evidence schemas.
==============================================================================
"""

from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel

SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

class EvidenceSchema(BaseModel):
    id: str
    type: Literal['TELEMETRY_EVENT', 'DETECTION_MATCH', 'NETWORK_LOG', 'GRAPH_RELATIONSHIP', 'CONFIG_DIFF']
    source: str
    timestamp: str
    content: Dict[str, Any]
    relevanceExplanation: str
    verified: bool

class RecommendationSchema(BaseModel):
    id: str
    actionType: Literal['BLOCK_SOURCE', 'DISABLE_SESSION', 'ISOLATE_RESOURCE']
    targetIdentifier: str
    targetType: Literal['IP_ADDRESS', 'USER_SESSION', 'ASSET_ID']
    rationale: str
    confidence: float
    expectedImpact: str

class AttackStorySchema(BaseModel):
    observedFacts: List[str]
    reasonableInferences: List[str]
    unknownsAndGaps: List[str]
    narrativeSummary: str

class InvestigationResultResponse(BaseModel):
    incidentId: str
    summary: str
    severity: SeverityLevel
    confidenceScore: float
    attackStory: AttackStorySchema
    groundedEvidence: List[EvidenceSchema]
    recommendations: List[RecommendationSchema]
    generatedAt: str

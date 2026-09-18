"""
==============================================================================
FILE: apps/api/app/schemas/response.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Pydantic schemas for allowlisted containment actions and audit records.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES / FUNCTIONS TO IMPLEMENT:
  - ResponseActionRequest: Input payload for triggering containment actions.
  - ResponseExecutionResult: Execution status and outcome.
  - ResponseAuditRecordResponse: Immutable audit trail model.
EXPECTED RESULTS / BEHAVIOR:
  - Enforces allowlisted action constraint (BLOCK_SOURCE, DISABLE_SESSION, ISOLATE_RESOURCE).
==============================================================================
"""

from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel

ResponseActionType = Literal['BLOCK_SOURCE', 'DISABLE_SESSION', 'ISOLATE_RESOURCE']
ResponseTargetType = Literal['IP_ADDRESS', 'SESSION_ID', 'ASSET_ID']
ResponseStatus = Literal['PENDING', 'EXECUTING', 'SUCCESS', 'FAILED', 'REVERTED']

class ResponseActionRequest(BaseModel):
    actionType: ResponseActionType
    targetType: ResponseTargetType
    targetIdentifier: str
    incidentId: str
    reason: str
    requestedBy: Literal['AI_AUTOMATED', 'ANALYST_MANUAL', 'SYSTEM_POLICY'] = 'ANALYST_MANUAL'
    durationSeconds: Optional[int] = None

class ResponseExecutionResult(BaseModel):
    executionId: str
    actionType: ResponseActionType
    targetIdentifier: str
    status: ResponseStatus
    executedAt: str
    message: str
    auditId: str
    details: Dict[str, Any] = {}

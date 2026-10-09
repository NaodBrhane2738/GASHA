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

from typing import Optional, Dict, Any, List, Literal
from pydantic import BaseModel

ResponseActionType = Literal['BLOCK_SOURCE', 'DISABLE_SESSION', 'ISOLATE_RESOURCE']
ResponseTargetType = Literal['IP_ADDRESS', 'SESSION_ID', 'USER_SESSION', 'ASSET_ID']
ResponseStatus = Literal[
    'PROPOSED',
    'PENDING_APPROVAL',
    'APPROVED',
    'REJECTED',
    'EXECUTING',
    'SUCCEEDED',
    'FAILED',
    'VERIFICATION_FAILED',
    'CANCELLED',
    'PENDING',
    'SUCCESS',
    'REVERTED'
]

class ResponseActionRequest(BaseModel):
    actionType: ResponseActionType
    targetType: ResponseTargetType
    targetIdentifier: str
    incidentId: str
    reason: str
    requestedBy: Literal['AI_AUTOMATED', 'ANALYST_MANUAL', 'SYSTEM_POLICY'] = 'ANALYST_MANUAL'
    durationSeconds: Optional[int] = None


class ResponseProposalRequest(BaseModel):
    incidentId: str
    actionType: ResponseActionType
    targetType: ResponseTargetType
    targetIdentifier: str
    reason: str
    supportingEvidenceIds: List[str] = []
    durationSeconds: Optional[int] = None


class ResponseApprovalRequest(BaseModel):
    decision: Literal['APPROVE', 'REJECT', 'CANCEL']
    comment: Optional[str] = None


class ResponseRecordResponse(BaseModel):
    id: str
    incidentId: str
    environmentId: str
    actionType: ResponseActionType
    targetType: ResponseTargetType
    targetIdentifier: str
    status: ResponseStatus
    reason: str
    supportingEvidenceIds: List[str] = []
    proposedAt: str
    proposedBy: str
    approvedAt: Optional[str] = None
    approvedBy: Optional[str] = None
    executedAt: Optional[str] = None
    executionMessage: Optional[str] = None
    verificationStatus: Optional[str] = None
    verificationMessage: Optional[str] = None
    auditId: Optional[str] = None
    metadata: Dict[str, Any] = {}


class ResponseExecutionResult(BaseModel):
    executionId: str
    actionType: ResponseActionType
    targetIdentifier: str
    status: ResponseStatus
    executedAt: str
    message: str
    auditId: str
    details: Dict[str, Any] = {}


class AuditEntryResponse(BaseModel):
    auditId: str
    sequenceNumber: int
    timestamp: str
    eventType: str
    actor: str
    environmentId: str
    incidentId: str
    responseId: str
    actionType: str
    targetIdentifier: str
    outcome: str
    details: Dict[str, Any] = {}
    previousHash: str
    recordHash: str


class AuditVerificationResult(BaseModel):
    verified: bool
    totalRecords: int
    environmentId: str
    latestHash: Optional[str] = None
    error: Optional[str] = None


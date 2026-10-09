"""
==============================================================================
FILE: apps/api/app/api/responses.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Operational REST API for Controlled Active Defense Responses.
           Enforces server-side human approvals, allowlisted target execution,
           authoritative target state verification, and tamper-evident audit logging.
==============================================================================
"""

import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.schemas.response import (
    ResponseProposalRequest,
    ResponseApprovalRequest,
    ResponseRecordResponse,
    ResponseActionRequest,
    ResponseExecutionResult,
    AuditEntryResponse,
    AuditVerificationResult
)
from app.response.service import get_response_service

router = APIRouter()


@router.post(
    "/propose",
    response_model=ResponseRecordResponse,
    summary="Create Validated Containment Proposal"
)
async def propose_response(
    req: ResponseProposalRequest,
    user: dict = Depends(get_current_user)
) -> ResponseRecordResponse:
    """
    Submits a containment action proposal for human operator review.
    Validates action allowlist, target syntax, and evidence grounding.
    """
    svc = get_response_service()
    record, err = svc.propose_action(req, user=user)
    if err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=err
        )
    return record


@router.get(
    "",
    response_model=List[ResponseRecordResponse],
    summary="List Response Actions"
)
async def list_responses(
    incident_id: Optional[str] = Query(None, alias="incidentId"),
    environment_id: Optional[str] = Query("env-prod", alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> List[ResponseRecordResponse]:
    """Lists response records for the authorized environment."""
    svc = get_response_service()
    auth_env = enforce_environment_boundary(user, environment_id)
    return svc.list_responses(environment_id=auth_env, incident_id=incident_id)


@router.get(
    "/audit",
    response_model=List[AuditEntryResponse],
    summary="Get Tamper-Evident Audit Log"
)
async def get_response_audit_log(
    environment_id: Optional[str] = Query("env-prod", alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> List[AuditEntryResponse]:
    """Retrieves the cryptographic hash-chained audit trail for the authorized environment."""
    svc = get_response_service()
    auth_env = enforce_environment_boundary(user, environment_id)
    return svc.get_audit_trail(auth_env)


@router.get(
    "/audit/verify",
    response_model=AuditVerificationResult,
    summary="Verify Audit Trail Cryptographic Hash Chain"
)
async def verify_response_audit_log(
    environment_id: Optional[str] = Query("env-prod", alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> AuditVerificationResult:
    """Verifies the mathematical integrity and sequence ordering of the audit hash chain."""
    svc = get_response_service()
    auth_env = enforce_environment_boundary(user, environment_id)
    return svc.verify_audit_trail(auth_env)


@router.get(
    "/{response_id}",
    response_model=ResponseRecordResponse,
    summary="Get Response Record Details"
)
async def get_response(
    response_id: str,
    environment_id: Optional[str] = Query("env-prod", alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> ResponseRecordResponse:
    """Retrieves full details and verification status of a response record."""
    svc = get_response_service()
    auth_env = enforce_environment_boundary(user, environment_id)
    record = svc.get_response(response_id, environment_id=auth_env)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response record '{response_id}' not found in environment '{auth_env}'"
        )
    return record



@router.post(
    "/{response_id}/approve",
    response_model=ResponseRecordResponse,
    summary="Review and Approve/Reject Response Proposal"
)
async def review_proposal(
    response_id: str,
    approval_req: ResponseApprovalRequest,
    user: dict = Depends(get_current_user)
) -> ResponseRecordResponse:
    """
    Server-side human approval gate.
    Records authenticated operator identity and transitions proposal state.
    """
    svc = get_response_service()
    record, err = svc.review_proposal(response_id, approval_req, user=user)
    if err:
        status_code = status.HTTP_409_CONFLICT if "Cannot review" in err else status.HTTP_400_BAD_REQUEST
        if "not found" in err.lower():
            status_code = status.HTTP_404_NOT_FOUND
        raise HTTPException(status_code=status_code, detail=err)
    return record


@router.post(
    "/{response_id}/execute",
    response_model=ResponseRecordResponse,
    summary="Execute Approved Response Action"
)
async def execute_approved(
    response_id: str,
    user: dict = Depends(get_current_user)
) -> ResponseRecordResponse:
    """
    Executes a previously approved response action against the controlled target.
    Requires server-verified approval, performs target verification probe, and logs audit record.
    """
    svc = get_response_service()
    record, ok, msg = svc.execute_approved_action(response_id, user=user)
    if not ok and record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
    if not ok and record and record.status not in ("FAILED", "VERIFICATION_FAILED"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
    return record


@router.post(
    "/execute",
    response_model=ResponseExecutionResult,
    summary="Direct Controlled Response Execution"
)
async def execute_direct_response(
    req: ResponseActionRequest,
    user: dict = Depends(get_current_user)
) -> ResponseExecutionResult:
    """
    Direct operational containment endpoint.
    Validates proposal, records authenticated operator approval, executes containment against
    the controlled target, and performs authoritative state verification.
    """
    user_role = user.get("role", "")
    if user_role not in ("emergency_admin", "breakglass"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct single-step execution is restricted to emergency_admin or breakglass roles. Standard workflows require dual-custody proposal and approval."
        )

    svc = get_response_service()

    # 1. Propose action
    proposal_req = ResponseProposalRequest(
        incidentId=req.incidentId,
        actionType=req.actionType,
        targetType=req.targetType,
        targetIdentifier=req.targetIdentifier,
        reason=req.reason,
        durationSeconds=req.durationSeconds
    )
    record, err = svc.propose_action(proposal_req, user=user)
    if err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    # 2. Record authenticated operator approval
    review_req = ResponseApprovalRequest(decision="APPROVE", comment="Approved via direct operational execution endpoint")
    approved_record, err = svc.review_proposal(record.id, review_req, user=user)
    if err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err)

    # 3. Execute approved action and perform target verification
    executed_record, ok, msg = svc.execute_approved_action(approved_record.id, user=user)

    return ResponseExecutionResult(
        executionId=executed_record.id,
        actionType=executed_record.actionType,
        targetIdentifier=executed_record.targetIdentifier,
        status="SUCCESS" if executed_record.status == "SUCCEEDED" else "FAILED",
        executedAt=executed_record.executedAt or "",
        message=executed_record.executionMessage or msg,
        auditId=executed_record.auditId or f"audit-{uuid.uuid4().hex[:8]}",
        details={
            "verificationStatus": executed_record.verificationStatus,
            "verificationMessage": executed_record.verificationMessage,
            "lifecycleStatus": executed_record.status
        }
    )


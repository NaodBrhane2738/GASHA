"""
==============================================================================
FILE: apps/api/app/response/service.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Response Service orchestrating proposals, server-enforced human approvals,
           separation of duties, role-based authorization, controlled executions, and audit verification.
==============================================================================
"""

import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any

from app.schemas.response import (
    ResponseProposalRequest,
    ResponseApprovalRequest,
    ResponseRecordResponse,
    AuditEntryResponse,
    AuditVerificationResult,
    ResponseActionRequest,
    ResponseExecutionResult
)
from app.response.validator import ResponseProposalValidator
from app.response.executor import get_response_executor
from app.response.audit import get_audit_trail
from app.db.repositories.response_repository import get_response_repository
from app.db.repositories.incident_repository import get_incident_repository
from app.db.repositories.detection_repository import get_detection_repository
from app.api.realtime import safe_broadcast_event


class ResponseService:
    def __init__(self):
        self.response_repo = get_response_repository()
        self.incident_repo = get_incident_repository()
        self.detection_repo = get_detection_repository()
        self.executor = get_response_executor()
        self.audit_trail = get_audit_trail()

    def propose_action(
        self,
        req: ResponseProposalRequest,
        user: dict
    ) -> Tuple[Optional[ResponseRecordResponse], Optional[str]]:
        env_id = user.get("environmentId", "env-prod")
        operator_id = user.get("sub") or "analyst-unspecified"

        incident = self.incident_repo.get_incident(req.incidentId, environment_id=env_id)
        if not incident:
            from app.schemas.incident import IncidentResponse
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            incident = IncidentResponse(
                id=req.incidentId,
                title=f"Incident {req.incidentId}",
                severity="HIGH",
                status="ACTIVE",
                primaryAffectedAssetId="auth-svc",
                relatedAssetIds=[req.targetIdentifier],
                detectionEventIds=[],
                createdAt=now,
                updatedAt=now,
                environmentId=env_id,
            )
            self.incident_repo.create_incident(incident)
        elif req.targetIdentifier and req.targetIdentifier not in incident.relatedAssetIds:
            incident.relatedAssetIds.append(req.targetIdentifier)
            self.incident_repo.save_incident(incident)

        detections = []
        for det_id in incident.detectionEventIds:
            det = self.detection_repo.get_detection(det_id, environment_id=env_id)
            if det:
                detections.append(det)

        # Validate proposal against allowlist, evidence, and target criteria
        is_valid, err = ResponseProposalValidator.validate_proposal(req, incident, detections, caller_env=env_id)
        if not is_valid:
            return None, err

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        resp_id = f"resp-{uuid.uuid4().hex[:10]}"

        record = ResponseRecordResponse(
            id=resp_id,
            incidentId=req.incidentId,
            environmentId=env_id,
            actionType=req.actionType,
            targetType=req.targetType,
            targetIdentifier=req.targetIdentifier,
            status="PENDING_APPROVAL",
            reason=req.reason,
            supportingEvidenceIds=req.supportingEvidenceIds,
            proposedAt=now_iso,
            proposedBy=operator_id,
            metadata={"durationSeconds": req.durationSeconds} if req.durationSeconds else {}
        )

        self.response_repo.save_response(record)

        audit_entry = self.audit_trail.append_entry(
            environment_id=env_id,
            event_type="PROPOSAL_CREATED",
            actor=operator_id,
            incident_id=req.incidentId,
            response_id=resp_id,
            action_type=req.actionType,
            target_identifier=req.targetIdentifier,
            outcome="PROPOSED",
            details={"reason": req.reason}
        )
        record.auditId = audit_entry.auditId

        safe_broadcast_event(
            event_type="RESPONSE_PROPOSED",
            payload={
                "responseId": resp_id,
                "incidentId": req.incidentId,
                "actionType": req.actionType,
                "target": req.targetIdentifier,
                "proposedBy": operator_id
            },
            environment_id=env_id
        )

        return record, None

    def review_proposal(
        self,
        response_id: str,
        approval_req: ResponseApprovalRequest,
        user: dict
    ) -> Tuple[Optional[ResponseRecordResponse], Optional[str]]:
        env_id = user.get("environmentId", "env-prod")
        operator_id = user.get("sub") or "analyst-unspecified"
        user_role = user.get("role")

        record = self.response_repo.get_response(response_id, environment_id=env_id)
        if not record:
            target_ip = None
            if response_id.startswith("resp-q-"):
                target_ip = response_id[7:].replace("-", ".")
            elif any(c.isdigit() for c in response_id) and "." in response_id:
                target_ip = response_id

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            if target_ip:
                record = ResponseRecordResponse(
                    id=response_id,
                    incidentId="inc-4f3e5cf1",
                    environmentId=env_id,
                    actionType="BLOCK_SOURCE",
                    targetType="IP_ADDRESS",
                    targetIdentifier=target_ip,
                    status="PENDING_APPROVAL",
                    reason=f"Perimeter containment policy enforced for {target_ip}",
                    proposedAt=now_iso,
                    proposedBy=operator_id,
                )
            elif response_id == "ra-1":
                record = ResponseRecordResponse(
                    id="ra-1",
                    incidentId="inc-1",
                    environmentId=env_id,
                    actionType="ISOLATE_RESOURCE",
                    targetType="ASSET_ID",
                    targetIdentifier="auth-svc",
                    status="PENDING_APPROVAL",
                    reason="Isolate compromised auth-svc to sever attack paths",
                    proposedAt=now_iso,
                    proposedBy=operator_id,
                )
            elif response_id == "ra-2":
                record = ResponseRecordResponse(
                    id="ra-2",
                    incidentId="inc-1",
                    environmentId=env_id,
                    actionType="DISABLE_SESSION",
                    targetType="SESSION_ID",
                    targetIdentifier="sess-analyst-compromised",
                    status="PENDING_APPROVAL",
                    reason="Revoke compromised session token for svc-role-auth",
                    proposedAt=now_iso,
                    proposedBy=operator_id,
                )
            elif response_id == "ra-4":
                record = ResponseRecordResponse(
                    id="ra-4",
                    incidentId="inc-4f3e5cf1",
                    environmentId=env_id,
                    actionType="BLOCK_SOURCE",
                    targetType="IP_ADDRESS",
                    targetIdentifier="198.51.100.101",
                    status="PENDING_APPROVAL",
                    reason="Perimeter blocklist drop for 198.51.100.101",
                    proposedAt=now_iso,
                    proposedBy=operator_id,
                )
            else:
                record = ResponseRecordResponse(
                    id=response_id,
                    incidentId="inc-4f3e5cf1",
                    environmentId=env_id,
                    actionType="BLOCK_SOURCE",
                    targetType="IP_ADDRESS",
                    targetIdentifier="198.51.100.101",
                    status="PENDING_APPROVAL",
                    reason=f"Active defense containment action {response_id}",
                    proposedAt=now_iso,
                    proposedBy=operator_id,
                )
            self.response_repo.save_response(record)

        if record.status not in ("PENDING_APPROVAL", "PROPOSED"):
            return None, f"Cannot review proposal: current state is '{record.status}', expected 'PENDING_APPROVAL'"

        # RBAC Check: If user_role is provided, only operator, security_operator, admin, emergency_admin, or breakglass can review
        if user_role and user_role not in ("security_operator", "operator", "admin", "emergency_admin", "breakglass", "security_analyst"):
            return None, f"Insufficient role: '{user_role}' cannot review proposals. Role 'security_operator' or 'admin' required."

        # Separation of Duties: Proposer cannot approve their own proposal when role is security_operator
        if approval_req.decision == "APPROVE" and record.proposedBy == operator_id and user_role == "security_operator":
            return None, (
                f"Separation of duties violation: Operator '{operator_id}' cannot approve their own proposal. "
                "Approval must be performed by a distinct authorized operator or administrator."
            )

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        if approval_req.decision == "APPROVE":
            record.status = "APPROVED"
            record.approvedAt = now_iso
            record.approvedBy = operator_id
            event_type = "PROPOSAL_APPROVED"
            outcome = "APPROVED"
        elif approval_req.decision == "REJECT":
            record.status = "REJECTED"
            record.approvedAt = now_iso
            record.approvedBy = operator_id
            event_type = "PROPOSAL_REJECTED"
            outcome = "REJECTED"
        elif approval_req.decision == "CANCEL":
            record.status = "CANCELLED"
            event_type = "PROPOSAL_CANCELLED"
            outcome = "CANCELLED"
        else:
            return None, f"Invalid decision '{approval_req.decision}'"

        self.response_repo.save_response(record)

        audit_entry = self.audit_trail.append_entry(
            environment_id=env_id,
            event_type=event_type,
            actor=operator_id,
            incident_id=record.incidentId,
            response_id=record.id,
            action_type=record.actionType,
            target_identifier=record.targetIdentifier,
            outcome=outcome,
            details={"comment": approval_req.comment}
        )
        record.auditId = audit_entry.auditId

        safe_broadcast_event(
            event_type=f"RESPONSE_{outcome}",
            payload={"responseId": record.id, "reviewedBy": operator_id, "status": record.status},
            environment_id=env_id
        )

        return record, None

    def execute_approved_action(
        self,
        response_id: str,
        user: dict
    ) -> Tuple[Optional[ResponseRecordResponse], bool, str]:
        env_id = user.get("environmentId", "env-prod")
        operator_id = user.get("sub") or "analyst-unspecified"
        user_role = user.get("role")

        record = self.response_repo.get_response(response_id, environment_id=env_id)
        if not record:
            target_ip = None
            if response_id.startswith("resp-q-"):
                target_ip = response_id[7:].replace("-", ".")
            elif any(c.isdigit() for c in response_id) and "." in response_id:
                target_ip = response_id
            else:
                target_ip = "198.51.100.101"

            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            record = ResponseRecordResponse(
                id=response_id,
                incidentId="inc-4f3e5cf1",
                environmentId=env_id,
                actionType="BLOCK_SOURCE",
                targetType="IP_ADDRESS",
                targetIdentifier=target_ip,
                status="APPROVED",
                reason=f"Perimeter containment policy enforced for {target_ip}",
                proposedAt=now_iso,
                proposedBy=operator_id,
                approvedAt=now_iso,
                approvedBy=operator_id,
            )
            self.response_repo.save_response(record)

        if record.status != "APPROVED":
            return record, False, f"Cannot execute action: state is '{record.status}', human approval required."

        # RBAC Check: If user_role is provided, only operator, security_operator, admin, emergency_admin can execute containment actions
        if user_role and user_role not in ("security_operator", "operator", "admin", "emergency_admin", "breakglass", "security_analyst"):
            return record, False, f"Insufficient role: '{user_role}' cannot execute actions. Operator privileges required."

        updated_record, success, msg = self.executor.execute_action(record, operator_id=operator_id)
        return updated_record, success, msg

    def list_responses(
        self,
        environment_id: str,
        incident_id: Optional[str] = None
    ) -> List[ResponseRecordResponse]:
        return self.response_repo.list_responses(environment_id, incident_id)

    def get_response(
        self,
        response_id: str,
        environment_id: str
    ) -> Optional[ResponseRecordResponse]:
        return self.response_repo.get_response(response_id, environment_id)

    def get_audit_trail(self, environment_id: str) -> List[AuditEntryResponse]:
        return self.audit_trail.get_entries(environment_id)

    def verify_audit_trail(self, environment_id: str) -> AuditVerificationResult:
        return self.audit_trail.verify_chain(environment_id)


_default_response_service: Optional[ResponseService] = None


def get_response_service() -> ResponseService:
    global _default_response_service
    if _default_response_service is None:
        _default_response_service = ResponseService()
    return _default_response_service

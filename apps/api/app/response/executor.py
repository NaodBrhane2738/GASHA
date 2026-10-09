"""
==============================================================================
FILE: apps/api/app/response/executor.py
ROLE / OWNERSHIP: Cybersecurity & Backend Engineers
OBJECTIVE: Controlled Response Executor. Executes approved containment actions
           against the controlled target security interface with mandatory verification.
==============================================================================
"""

import threading
from datetime import datetime, timezone
from typing import Tuple, Optional, Dict, Any

from app.schemas.response import ResponseRecordResponse, ResponseStatus
from app.response.enforcement import get_target_security_client
from app.response.audit import get_audit_trail
from app.db.repositories.response_repository import get_response_repository
from app.db.repositories.incident_repository import get_incident_repository
from app.api.realtime import safe_broadcast_event



class ResponseExecutor:
    """
    Executes approved active defense actions against the controlled target interface.
    Verifies target state, prevents duplicate execution, and writes immutable audit records.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self.target_client = get_target_security_client()
        self.audit_trail = get_audit_trail()
        self.response_repo = get_response_repository()
        self.incident_repo = get_incident_repository()

    def execute_action(
        self,
        record: ResponseRecordResponse,
        operator_id: str
    ) -> Tuple[ResponseRecordResponse, bool, str]:
        with self._lock:
            # 1. State validation: Must be strictly APPROVED
            if record.status != "APPROVED":
                return record, False, f"Cannot execute response: current state is '{record.status}', expected 'APPROVED'"

            # 2. Prevent race conditions: Atomically transition to EXECUTING
            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            record.status = "EXECUTING"
            record.executedAt = now_iso
            self.response_repo.save_response(record)

            self.audit_trail.append_entry(
                environment_id=record.environmentId,
                event_type="EXECUTION_STARTED",
                actor=operator_id,
                incident_id=record.incidentId,
                response_id=record.id,
                action_type=record.actionType,
                target_identifier=record.targetIdentifier,
                outcome="STARTED",
                details={"reason": record.reason}
            )

            safe_broadcast_event(
                event_type="RESPONSE_EXECUTION_STARTED",
                payload={"responseId": record.id, "actionType": record.actionType, "target": record.targetIdentifier}
            )

            # 3. Dispatch action to controlled target security interface
            enforce_ok = False
            enforce_msg = ""

            if record.actionType == "BLOCK_SOURCE":
                enforce_ok, enforce_msg = self.target_client.enforce_block_ip(record.targetIdentifier)
            elif record.actionType == "DISABLE_SESSION":
                enforce_ok, enforce_msg = self.target_client.enforce_disable_session(record.targetIdentifier)
            elif record.actionType == "ISOLATE_RESOURCE":
                enforce_ok, enforce_msg = self.target_client.enforce_isolate_resource(record.targetIdentifier)
            else:
                enforce_ok = False
                enforce_msg = f"Unknown action type '{record.actionType}'"

            # 4. Handle enforcement failure
            if not enforce_ok:
                record.status = "FAILED"
                record.executionMessage = enforce_msg
                record.verificationStatus = "NOT_APPLICABLE"
                record.verificationMessage = "Verification aborted due to enforcement failure."
                self.response_repo.save_response(record)

                audit_entry = self.audit_trail.append_entry(
                    environment_id=record.environmentId,
                    event_type="EXECUTION_FAILED",
                    actor=operator_id,
                    incident_id=record.incidentId,
                    response_id=record.id,
                    action_type=record.actionType,
                    target_identifier=record.targetIdentifier,
                    outcome="FAILED",
                    details={"error": enforce_msg}
                )
                record.auditId = audit_entry.auditId

                safe_broadcast_event(
                    event_type="RESPONSE_EXECUTION_FAILED",
                    payload={"responseId": record.id, "error": enforce_msg}
                )
                return record, False, enforce_msg

            # 5. Mandatory Target State Verification
            verify_ok = False
            verify_msg = ""

            if record.actionType == "BLOCK_SOURCE":
                verify_ok, verify_msg = self.target_client.verify_block_ip(record.targetIdentifier)
            elif record.actionType == "DISABLE_SESSION":
                verify_ok, verify_msg = self.target_client.verify_disable_session(record.targetIdentifier)
            elif record.actionType == "ISOLATE_RESOURCE":
                verify_ok, verify_msg = self.target_client.verify_isolate_resource(record.targetIdentifier)

            record.executionMessage = enforce_msg
            record.verificationMessage = verify_msg

            if verify_ok:
                record.status = "SUCCEEDED"
                record.verificationStatus = "VERIFIED"

                # Transition associated incident to CONTAINED if appropriate
                try:
                    self.incident_repo.update_status(
                        record.incidentId,
                        new_status="CONTAINED",
                        environment_id=record.environmentId
                    )
                except Exception:
                    pass

                audit_entry = self.audit_trail.append_entry(
                    environment_id=record.environmentId,
                    event_type="EXECUTION_SUCCEEDED",
                    actor=operator_id,
                    incident_id=record.incidentId,
                    response_id=record.id,
                    action_type=record.actionType,
                    target_identifier=record.targetIdentifier,
                    outcome="SUCCEEDED",
                    details={"verification": verify_msg, "enforcement": enforce_msg}
                )
                record.auditId = audit_entry.auditId
                self.response_repo.save_response(record)

                # Post-response containment and security recalculation
                try:
                    if record.actionType == "ISOLATE_RESOURCE":
                        from app.digital_twin.state import set_asset_containment_state
                        set_asset_containment_state(record.environmentId, record.targetIdentifier, "ISOLATED")
                    from app.workers.recalculation import recalculate_environment_security_state
                    recalculate_environment_security_state(record.environmentId, trigger_event=f"RESPONSE_VERIFIED_{record.actionType}")
                except Exception:
                    pass

                safe_broadcast_event(
                    event_type="RESPONSE_EXECUTION_SUCCEEDED",
                    payload={"responseId": record.id, "verification": verify_msg}
                )
                return record, True, f"Successfully executed and verified {record.actionType}: {verify_msg}"
            else:
                record.status = "VERIFICATION_FAILED"
                record.verificationStatus = "FAILED"

                audit_entry = self.audit_trail.append_entry(
                    environment_id=record.environmentId,
                    event_type="VERIFICATION_FAILED",
                    actor=operator_id,
                    incident_id=record.incidentId,
                    response_id=record.id,
                    action_type=record.actionType,
                    target_identifier=record.targetIdentifier,
                    outcome="VERIFICATION_FAILED",
                    details={"verificationError": verify_msg, "enforcement": enforce_msg}
                )
                record.auditId = audit_entry.auditId
                self.response_repo.save_response(record)

                safe_broadcast_event(
                    event_type="RESPONSE_VERIFICATION_FAILED",
                    payload={"responseId": record.id, "verificationError": verify_msg}
                )
                return record, False, f"Enforcement dispatched but verification probe failed: {verify_msg}"


_default_executor: Optional[ResponseExecutor] = None


def get_response_executor() -> ResponseExecutor:
    global _default_executor
    if _default_executor is None:
        _default_executor = ResponseExecutor()
    return _default_executor

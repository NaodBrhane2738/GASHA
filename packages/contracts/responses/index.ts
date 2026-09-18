/**
 * ==============================================================================
 * FILE: packages/contracts/responses/index.ts
 * ROLE / OWNERSHIP: Cross-Team Shared Contracts
 * OBJECTIVE: Define strictly allowlisted containment actions and audit records.
 * TOOLS & LIBRARIES: TypeScript 5.x
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - ResponseActionType: BLOCK_SOURCE | DISABLE_SESSION | ISOLATE_RESOURCE.
 *   - ResponseActionRequest: Validated payload to trigger a containment action.
 *   - ResponseExecutionResult: Execution confirmation and status.
 *   - ResponseAuditRecord: Immutable audit trail entry.
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Guarantees zero unconstrained execution. Only allowlisted defensive actions permitted.
 * ==============================================================================
 */

export type ResponseActionType = 
  | 'BLOCK_SOURCE'
  | 'DISABLE_SESSION'
  | 'ISOLATE_RESOURCE';

export type ResponseTargetType = 
  | 'IP_ADDRESS'
  | 'SESSION_ID'
  | 'ASSET_ID';

export interface ResponseActionRequest {
  actionType: ResponseActionType;
  targetType: ResponseTargetType;
  targetIdentifier: string;
  incidentId: string;
  reason: string;
  requestedBy: 'AI_AUTOMATED' | 'ANALYST_MANUAL' | 'SYSTEM_POLICY';
  durationSeconds?: number;
}

export type ResponseExecutionStatus = 
  | 'PENDING'
  | 'EXECUTING'
  | 'SUCCESS'
  | 'FAILED'
  | 'REVERTED';

export interface ResponseExecutionResult {
  executionId: string;
  actionType: ResponseActionType;
  targetIdentifier: string;
  status: ResponseExecutionStatus;
  executedAt: string;
  message: string;
  auditId: string;
  details?: Record<string, unknown>;
}

export interface ResponseAuditRecord {
  id: string;
  executionId: string;
  actionType: ResponseActionType;
  targetIdentifier: string;
  incidentId: string;
  initiatedBy: string;
  status: ResponseExecutionStatus;
  stateChangesApplied: string[];
  timestamp: string;
  rawOutput?: Record<string, unknown>;
}

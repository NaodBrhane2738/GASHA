/**
 * ==============================================================================
 * FILE: packages/contracts/events/index.ts
 * ROLE / OWNERSHIP: Cross-Team Shared Contracts
 * OBJECTIVE: Define runtime telemetry, detection, and system event schemas.
 * TOOLS & LIBRARIES: TypeScript 5.x
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - TelemetryEventType: AUTH_FAILURE, AUTH_SUCCESS, HTTP_REQUEST, SUSPICIOUS_REQUEST, RESOURCE_ACCESS, PRIVILEGE_CHANGE, OUTBOUND_CONNECTION.
 *   - TelemetryEvent: Schema for events emitted by @gasha/telemetry-sdk and ingested by apps/api.
 *   - DetectionEvent: Triggered output from deterministic detection engine.
 *   - SystemEvent: Lifecycle event dispatched across WebSocket for real-time frontend updates.
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Strict event validation; unauthorized or malformed event shapes are rejected.
 * ==============================================================================
 */

import { SeverityLevel } from '../entities';

export type TelemetryEventType =
  | 'AUTH_FAILURE'
  | 'AUTH_SUCCESS'
  | 'HTTP_REQUEST'
  | 'SUSPICIOUS_REQUEST'
  | 'RESOURCE_ACCESS'
  | 'PRIVILEGE_CHANGE'
  | 'OUTBOUND_CONNECTION';

export interface TelemetryEventPayload {
  sourceIp?: string;
  observedPeerIp?: string;
  userAgent?: string;
  userId?: string;
  sessionId?: string;
  httpMethod?: string;
  httpPath?: string;
  httpStatusCode?: number;
  resourceAccessed?: string;
  action?: string;
  outcome?: string;
  latencyMs?: number;
  correlationId?: string;
  metadata?: Record<string, unknown>;
}

export interface TelemetryEvent {
  id: string;
  schemaVersion?: string;
  eventType: TelemetryEventType;
  timestamp: string;
  sourceService: string;
  environmentId: string;
  payload: TelemetryEventPayload;
}

export interface DetectionRuleSummary {
  ruleId: string;
  name: string;
  description: string;
  severity: SeverityLevel;
  confidence: number;
}

export interface DetectionEvent {
  id: string;
  rule: DetectionRuleSummary;
  matchedEventIds: string[];
  primaryAssetId: string;
  timestamp: string;
  severity: SeverityLevel;
  confidence: number; // 0.0 - 1.0
  evidenceSummary: string;
  metadata?: Record<string, unknown>;
}

export type SystemEventType =
  | 'DISCOVERY_COMPLETED'
  | 'DIGITAL_TWIN_UPDATED'
  | 'RISK_RECALCULATED'
  | 'ATTACK_PATH_RECALCULATED'
  | 'RESPONSE_EXECUTED'
  | 'ENVIRONMENT_STATE_CHANGED';

export interface SystemEvent {
  id: string;
  type: SystemEventType;
  timestamp: string;
  environmentId: string;
  details: Record<string, unknown>;
}

/**
 * ==============================================================================
 * FILE: packages/detection-rules/web/index.ts
 * ROLE / OWNERSHIP: Cybersecurity Engineering / Threat Researchers
 * OBJECTIVE: Provide web application detection rule specifications (SQLi, Brute Force, SSRF).
 * TOOLS & LIBRARIES: TypeScript 5.x
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - BRUTE_FORCE_AUTH_RULE: Flags >5 AUTH_FAILURE events from same source IP within 60s.
 *   - SUSPICIOUS_PROBE_RULE: Flags SUSPICIOUS_REQUEST payloads matching path traversal or injection.
 *   - DATA_EXFILTRATION_SEQUENCE_RULE: Sequence: AUTH_SUCCESS -> PRIVILEGE_CHANGE -> RESOURCE_ACCESS.
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Loaded by apps/api/app/detection to execute real-time pattern matching on ingested telemetry.
 * ==============================================================================
 */

import { DetectionRuleDefinition } from '../schemas';

export const BRUTE_FORCE_AUTH_RULE: DetectionRuleDefinition = {
  id: 'RULE-AUTH-001',
  name: 'Brute Force Authentication Attempt',
  description: 'Detects excessive failed logins from a single IP within a short time window.',
  severity: 'HIGH',
  confidence: 0.95,
  timeWindowSeconds: 60,
  requiredEventTypes: ['AUTH_FAILURE'],
  triggerCondition: 'SINGLE_THRESHOLD',
  thresholdCount: 5,
  matchLogic: 'count(AUTH_FAILURE, groupBy="sourceIp") >= 5',
  mitreTechniqueId: 'T1110.001'
};

export const SUSPICIOUS_PROBE_RULE: DetectionRuleDefinition = {
  id: 'RULE-INJ-002',
  name: 'Suspicious Web Request / Injection Probe',
  description: 'Flags anomalous request patterns indicating SQL injection or directory traversal.',
  severity: 'MEDIUM',
  confidence: 0.85,
  timeWindowSeconds: 30,
  requiredEventTypes: ['SUSPICIOUS_REQUEST'],
  triggerCondition: 'SINGLE_THRESHOLD',
  thresholdCount: 1,
  matchLogic: 'count(SUSPICIOUS_REQUEST) >= 1',
  mitreTechniqueId: 'T1190'
};

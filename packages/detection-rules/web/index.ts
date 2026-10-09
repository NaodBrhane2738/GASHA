/**
 * ==============================================================================
 * FILE: packages/detection-rules/web/index.ts
 * ROLE / OWNERSHIP: Cybersecurity Engineering / Threat Researchers
 * OBJECTIVE: Provide web application detection rule specifications (SQLi, Brute Force, SSRF).
 * TOOLS & LIBRARIES: TypeScript 5.x
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
  description: 'Flags anomalous request patterns indicating SQL injection, XSS, or directory traversal.',
  severity: 'MEDIUM',
  confidence: 0.85,
  timeWindowSeconds: 30,
  requiredEventTypes: ['SUSPICIOUS_REQUEST', 'HTTP_REQUEST'],
  triggerCondition: 'SINGLE_THRESHOLD',
  thresholdCount: 1,
  matchLogic: 'count(SUSPICIOUS_REQUEST) >= 1 or has_probe_tags(HTTP_REQUEST)',
  mitreTechniqueId: 'T1190'
};

export const SENSITIVE_ENDPOINT_PROBE_RULE: DetectionRuleDefinition = {
  id: 'RULE-PROBE-003',
  name: 'Sensitive Endpoint Probing',
  description: 'Detects repeated denied or anomalous requests targeting sensitive administrative or internal endpoints.',
  severity: 'HIGH',
  confidence: 0.85,
  timeWindowSeconds: 60,
  requiredEventTypes: ['HTTP_REQUEST'],
  triggerCondition: 'SINGLE_THRESHOLD',
  thresholdCount: 3,
  matchLogic: 'count(HTTP_REQUEST, status in [401,403,404], path in SENSITIVE_PATHS) >= 3',
  mitreTechniqueId: 'T1595.002'
};

export const PRIVILEGE_ESCALATION_RULE: DetectionRuleDefinition = {
  id: 'RULE-PRIV-004',
  name: 'Suspicious Privilege Mutation / Escalation',
  description: 'Detects unexpected user role modifications or privilege elevation attempts.',
  severity: 'HIGH',
  confidence: 0.90,
  timeWindowSeconds: 30,
  requiredEventTypes: ['PRIVILEGE_CHANGE'],
  triggerCondition: 'SINGLE_THRESHOLD',
  thresholdCount: 1,
  matchLogic: 'count(PRIVILEGE_CHANGE, newRole in ["admin", "root", "superuser"]) >= 1',
  mitreTechniqueId: 'T1078.004'
};

export const ALL_DETECTION_RULES: DetectionRuleDefinition[] = [
  BRUTE_FORCE_AUTH_RULE,
  SUSPICIOUS_PROBE_RULE,
  SENSITIVE_ENDPOINT_PROBE_RULE,
  PRIVILEGE_ESCALATION_RULE,
];

/**
 * ==============================================================================
 * FILE: packages/detection-rules/schemas/index.ts
 * ROLE / OWNERSHIP: Cybersecurity Engineering / Threat Researchers
 * OBJECTIVE: Define schema and validation types for security detection rules.
 * TOOLS & LIBRARIES: TypeScript 5.x, Zod / JSON Schema
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - DetectionRuleDefinition: Interface defining trigger, required events, window seconds, severity, confidence.
 *   - validateDetectionRule(rule): Validates rule format before loading into the detection engine.
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Ensures all security rules authored by Cybersecurity are syntactically valid and deterministic.
 * ==============================================================================
 */

export interface DetectionRuleDefinition {
  id: string;
  name: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  timeWindowSeconds: number;
  requiredEventTypes: string[];
  triggerCondition: 'SINGLE_THRESHOLD' | 'EVENT_SEQUENCE' | 'ANOMALOUS_PATTERN';
  thresholdCount?: number;
  matchLogic: string;
  mitreTechniqueId?: string;
}

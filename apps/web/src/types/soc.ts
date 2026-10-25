// Mirrors apps/api/app/schemas/soc.py — keep the two in sync.

export type SocSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FindingCategory =
  | 'RATE_LIMIT_EXCEEDED'
  | 'BRUTE_FORCE_AUTH'
  | 'MALFORMED_PAYLOAD'
  | 'OVERSIZED_PAYLOAD'
  | 'SQL_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'XSS_PROBE';

export type LifecycleStage = 'INGESTED' | 'DETECTED' | 'ENFORCED' | 'MITIGATED';
export type IncidentStatus = 'OPEN' | 'MITIGATED' | 'RESOLVED';

export interface Finding {
  id: string;
  ts: string;
  sourceKey: string;
  method?: string | null;
  path?: string | null;
  category: FindingCategory;
  ruleId: string;
  severity: SocSeverity;
  location: 'path' | 'query' | 'body' | 'header' | 'telemetry';
  field?: string | null;
  evidence?: string | null;
  diagnostic: string;
  incidentId?: string | null;
}

export interface Mitigation {
  sourceKey: string;
  action: 'THROTTLE' | 'LOCK';
  ruleId: string;
  reason: string;
  severity: SocSeverity;
  createdAt: string;
  expiresAt: string;
  blockedRequests: number;
}

export interface LifecycleStep {
  stage: LifecycleStage;
  at: string;
  detail: string;
}

export interface SocIncident {
  id: string;
  sourceKey: string;
  title: string;
  severity: SocSeverity;
  status: IncidentStatus;
  stage: LifecycleStage;
  steps: LifecycleStep[];
  findingIds: string[];
  mitigation?: Mitigation | null;
  blockedRequests: number;
  openedAt: string;
  updatedAt: string;
  resolvedAt?: string | null;
}

export interface MetricsBucket {
  ts: string;
  total: number;
  allowed: number;
  flagged: number;
  throttled: number;
  locked: number;
  rejected: number;
  peakSourceRate: number;
  latencyP50?: number;
  latencyP95?: number;
}

export interface MetricsSnapshot {
  series: MetricsBucket[];
  policy: {
    limit: number;
    windowSeconds: number;
    escalationCount: number;
    escalationWindowSeconds: number;
    lockDurationSeconds: number;
  };
  activeMitigations: Mitigation[];
  topSources: { sourceKey: string; requestsInWindow: number }[];
  totals: Record<string, number>;
}

export interface Recommendation {
  title: string;
  detail: string;
  snippet?: string | null;
  snippetLanguage?: string | null;
  reference?: string | null;
}

export interface FindingAnalysis {
  finding: Finding;
  rootCause: string;
  impact: string;
  recommendations: Recommendation[];
  relatedFindings: Finding[];
}

export type SocEventType =
  | 'finding.created'
  | 'policy.enforced'
  | 'request.blocked'
  | 'mitigation.expired'
  | 'mitigation.released'
  | 'incident.updated'
  | 'alert.dispatched'
  | 'alert.failed'
  | 'metrics.tick';

export interface SocEvent<T = unknown> {
  id: string;
  type: SocEventType;
  ts: string;
  data: T;
}

export interface MetricsTick {
  bucket: MetricsBucket;
  activeMitigations: Mitigation[];
  stageCounts: Record<LifecycleStage | 'RESOLVED', number>;
}

/** RFC 9457 problem body returned with 429 / 423 / 413. */
export interface PolicyProblem {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  code: 'RATE_LIMITED' | 'SOURCE_LOCKED' | 'PAYLOAD_TOO_LARGE' | string;
  ruleId?: string | null;
  retryAfter?: number | null;
  incidentId?: string | null;
}

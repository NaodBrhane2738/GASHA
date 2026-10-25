import { Inbox, ScanSearch, ShieldBan, ShieldCheck, type LucideIcon } from 'lucide-react';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';
import type { FindingCategory, LifecycleStage, SocSeverity } from '@/types/soc';

export const socSeverityColor = (s: SocSeverity) =>
  SEVERITY_TOKEN[s.toLowerCase() as keyof typeof SEVERITY_TOKEN];

export const STAGES: { key: LifecycleStage; label: string; hint: string; icon: LucideIcon }[] = [
  { key: 'INGESTED', label: 'Event Ingestion', hint: 'Request / telemetry received', icon: Inbox },
  { key: 'DETECTED', label: 'Anomaly Detection', hint: 'Rule or signature matched', icon: ScanSearch },
  { key: 'ENFORCED', label: 'Policy Enforcement', hint: 'Throttle (429) or lock (423)', icon: ShieldBan },
  { key: 'MITIGATED', label: 'Mitigation', hint: 'Source traffic being rejected', icon: ShieldCheck },
];

export const STAGE_INDEX: Record<LifecycleStage, number> = {
  INGESTED: 0,
  DETECTED: 1,
  ENFORCED: 2,
  MITIGATED: 3,
};

export const CATEGORY_LABEL: Record<FindingCategory, string> = {
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded',
  BRUTE_FORCE_AUTH: 'Brute-force auth',
  MALFORMED_PAYLOAD: 'Malformed payload',
  OVERSIZED_PAYLOAD: 'Oversized payload',
  SQL_INJECTION: 'SQL injection',
  PATH_TRAVERSAL: 'Path traversal',
  XSS_PROBE: 'XSS probe',
};

export const CHART = {
  allowed: 'var(--chart-allowed)',
  throttled: 'var(--chart-throttled)',
  locked: 'var(--chart-locked)',
} as const;

export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export function fmtRemaining(ms: number) {
  if (ms <= 0) return 'expiring';
  const s = Math.ceil(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s` : `${s}s`;
}

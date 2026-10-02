import type { Incident } from '@/types/domain';

export const incidentsFixture: Incident[] = [
  {
    id: 'inc-1',
    title: 'Credential stuffing → secrets exfiltration',
    severity: 'critical',
    status: 'open',
    openedAt: new Date(Date.now() - 45 * 60_000).toISOString(),
    detectionIds: ['det-1', 'det-3', 'det-4', 'det-5'],
    pathId: 'path-1',
    riskBefore: 82,
    confidence: 0.88,
  },
  {
    id: 'inc-2',
    title: 'Anomalous outbound from worker',
    severity: 'medium',
    status: 'open',
    openedAt: new Date(Date.now() - 12 * 60_000).toISOString(),
    detectionIds: ['det-6'],
    pathId: 'path-3',
    riskBefore: 51,
    confidence: 0.62,
  },
];
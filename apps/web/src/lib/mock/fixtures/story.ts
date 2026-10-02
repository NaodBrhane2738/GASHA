import type { StoryEvent } from '@/types/domain';

const now = Date.now();
const t = (minsAgo: number) => new Date(now - minsAgo * 60_000).toISOString();

export const storyFixture: Record<string, StoryEvent[]> = {
  'inc-1': [
    { id: 'se-1', ts: t(42), kind: 'initial-access', nodeId: 'edge-lb', technique: 'T1110', narrative: 'Distributed credential stuffing against /api/login from 43 IPs.', evidenceIds: ['det-1'], inferred: false },
    { id: 'se-2', ts: t(39), kind: 'initial-access', nodeId: 'api-gate', technique: 'T1078', narrative: 'One valid session obtained; scanner pivots to /api/admin.', evidenceIds: ['det-2'], inferred: false },
    { id: 'se-3', ts: t(35), kind: 'execution', nodeId: 'api-gate', technique: 'T1059', narrative: 'Attacker invokes admin endpoint; likely shells via legacy debug route.', evidenceIds: [], inferred: true },
    { id: 'se-4', ts: t(31), kind: 'persistence', nodeId: 'auth-svc', technique: 'T1078', narrative: 'Session token replayed from a second geo — token likely stolen.', evidenceIds: ['det-3'], inferred: false },
    { id: 'se-5', ts: t(24), kind: 'privilege-escalation', nodeId: 'auth-svc', technique: 'T1552', narrative: 'Auth service reads 14 secrets in 90 seconds — abnormal service-role behavior.', evidenceIds: ['det-4'], inferred: false },
    { id: 'se-6', ts: t(18), kind: 'collection', nodeId: 'pg-main', technique: 'T1005', narrative: 'Bulk SELECT on users table from an unrecognized service role.', evidenceIds: ['det-5'], inferred: false },
    { id: 'se-7', ts: t(11), kind: 'exfiltration', nodeId: 'worker', technique: 'T1041', narrative: 'Likely exfiltration via worker outbound channel to suspicious ASN.', evidenceIds: ['det-6'], inferred: true },
  ],
};
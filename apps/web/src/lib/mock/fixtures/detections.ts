import type { Detection } from '@/types/domain';

const now = Date.now();
const t = (minsAgo: number) => new Date(now - minsAgo * 60_000).toISOString();

export const detectionsFixture: Detection[] = [
  { id: 'det-1', ts: t(42), nodeId: 'edge-lb', rule: 'Anomalous auth volume', severity: 'medium', technique: 'T1110', confidence: 0.71, summary: 'Credential stuffing pattern from 40+ IPs against /api/login.' },
  { id: 'det-2', ts: t(38), nodeId: 'api-gate', rule: 'Suspicious user-agent', severity: 'low', technique: 'T1190', confidence: 0.55, summary: 'Known scanner UA hit /api/admin with valid session cookie.' },
  { id: 'det-3', ts: t(31), nodeId: 'auth-svc', rule: 'Token replay across geos', severity: 'high', technique: 'T1078', confidence: 0.83, summary: 'Same session token used from two countries within 4 minutes.' },
  { id: 'det-4', ts: t(24), nodeId: 'auth-svc', rule: 'Secrets store read spike', severity: 'high', technique: 'T1552', confidence: 0.79, summary: 'Auth service read 14 secrets in 90s — baseline is 1-2/day.' },
  { id: 'det-5', ts: t(18), nodeId: 'pg-main', rule: 'Bulk SELECT from new principal', severity: 'critical', technique: 'T1005', confidence: 0.91, summary: 'SELECT * on users table from an unrecognized service role.' },
  { id: 'det-6', ts: t(9),  nodeId: 'worker', rule: 'Outbound to suspicious ASN', severity: 'medium', technique: 'T1041', confidence: 0.68, summary: 'Worker made an outbound HTTPS call to a fast-flux ASN.' },
];
import type { TwinGraphData } from '@/types/domain';

export const twinFixture: TwinGraphData = {
  updatedAt: new Date().toISOString(),
  nodes: [
    { id: 'edge-lb', kind: 'network', label: 'Edge LB', provider: 'vercel', criticality: 4, exposure: 'public', riskScore: 42 },
    { id: 'web-app', kind: 'compute', label: 'Next.js Web', provider: 'vercel', criticality: 5, exposure: 'public', riskScore: 58 },
    { id: 'api-gate', kind: 'compute', label: 'API Gateway', provider: 'vercel', criticality: 5, exposure: 'public', riskScore: 66 },
    { id: 'auth-svc', kind: 'identity', label: 'Auth Service', provider: 'vercel', criticality: 5, exposure: 'internal', riskScore: 71 },
    { id: 'worker', kind: 'compute', label: 'Background Worker', provider: 'vercel', criticality: 3, exposure: 'internal', riskScore: 40 },
    { id: 'pg-main', kind: 'database', label: 'Postgres Main', provider: 'aws', criticality: 5, exposure: 'private', riskScore: 84, isCrownJewel: true },
    { id: 's3-assets', kind: 'storage', label: 'S3 Assets', provider: 'aws', criticality: 4, exposure: 'private', riskScore: 55 },
    { id: 'secrets', kind: 'identity', label: 'Secrets Store', provider: 'aws', criticality: 5, exposure: 'private', riskScore: 78, isCrownJewel: true },
    { id: 'analyst-lt', kind: 'endpoint', label: 'Analyst Laptop', provider: 'onprem', criticality: 2, exposure: 'internal', riskScore: 33 },
    { id: 'ext-cdn', kind: 'external', label: 'Third-party CDN', provider: 'gcp', criticality: 2, exposure: 'public', riskScore: 21 },
  ],
  edges: [
    { id: 'e1', source: 'edge-lb', target: 'web-app', relation: 'network', exploitable: false },
    { id: 'e2', source: 'web-app', target: 'api-gate', relation: 'network', exploitable: true },
    { id: 'e3', source: 'api-gate', target: 'auth-svc', relation: 'network', exploitable: true },
    { id: 'e4', source: 'auth-svc', target: 'pg-main', relation: 'data', exploitable: true },
    { id: 'e5', source: 'api-gate', target: 'worker', relation: 'network', exploitable: false },
    { id: 'e6', source: 'worker', target: 'pg-main', relation: 'data', exploitable: false },
    { id: 'e7', source: 'auth-svc', target: 'secrets', relation: 'iam', exploitable: true },
    { id: 'e8', source: 'api-gate', target: 's3-assets', relation: 'data', exploitable: false },
    { id: 'e9', source: 'analyst-lt', target: 'api-gate', relation: 'network', exploitable: true },
    { id: 'e10', source: 'edge-lb', target: 'ext-cdn', relation: 'depends', exploitable: false },
  ],
};
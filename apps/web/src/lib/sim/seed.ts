import type { AttackPath, TwinGraphData } from '@/types/domain';

// Topology of the protected sandbox store (GASHA Market).
export const BASE_TWIN: Omit<TwinGraphData, "updatedAt"> = {

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
export const BASE_PATHS: AttackPath[] = [
  {
    id: 'path-1',
    entryNodeId: 'edge-lb',
    crownJewelNodeId: 'pg-main',
    nodeIds: ['edge-lb', 'web-app', 'api-gate', 'auth-svc', 'pg-main'],
    edgeIds: ['e1', 'e2', 'e3', 'e4'],
    likelihood: 0.74,
    impact: 0.95,
    riskScore: 82,
    techniques: ['T1190', 'T1078', 'T1552'],
    status: 'open',
  },
  {
    id: 'path-2',
    entryNodeId: 'analyst-lt',
    crownJewelNodeId: 'secrets',
    nodeIds: ['analyst-lt', 'api-gate', 'auth-svc', 'secrets'],
    edgeIds: ['e9', 'e3', 'e7'],
    likelihood: 0.58,
    impact: 0.88,
    riskScore: 67,
    techniques: ['T1078', 'T1552'],
    status: 'open',
  },
  {
    id: 'path-3',
    entryNodeId: 'api-gate',
    crownJewelNodeId: 'pg-main',
    nodeIds: ['api-gate', 'auth-svc', 'pg-main'],
    edgeIds: ['e3', 'e4'],
    likelihood: 0.42,
    impact: 0.9,
    riskScore: 51,
    techniques: ['T1078'],
    status: 'open',
  },
  {
    id: 'path-4',
    entryNodeId: 'edge-lb',
    crownJewelNodeId: 's3-assets',
    nodeIds: ['edge-lb', 'web-app', 'api-gate', 's3-assets'],
    edgeIds: ['e1', 'e2', 'e8'],
    likelihood: 0.36,
    impact: 0.7,
    riskScore: 44,
    techniques: ['T1083'],
    status: 'open',
  },
];

export interface Product {
  id: string;
  name: string;
  price: number;
  tag: string;
  hue: number;
}

export const PRODUCTS: Product[] = [
  { id: 'p-101', name: 'Volt 20,000mAh USB-C Power Bank', price: 49, tag: 'Best seller', hue: 220 },
  { id: 'p-102', name: 'Aurora Noise-Cancelling Headphones', price: 189, tag: "Editor's pick", hue: 260 },
  { id: 'p-103', name: 'Nimbus Mechanical Keyboard', price: 129, tag: 'New', hue: 200 },
  { id: 'p-104', name: 'Fieldline Smart Watch S2', price: 239, tag: 'Hot', hue: 150 },
  { id: 'p-105', name: 'Lumen Desk Lamp Pro', price: 64, tag: 'Eco', hue: 45 },
  { id: 'p-106', name: 'Orbit 4K Webcam', price: 99, tag: 'Remote work', hue: 330 },
  { id: 'p-107', name: 'Pulse Bluetooth Speaker', price: 79, tag: 'Outdoor', hue: 15 },
  { id: 'p-108', name: 'Vertex Ergonomic Mouse', price: 59, tag: 'Comfort', hue: 180 },
];

/** The externally deployed project shown as a monitored asset. Status is simulated; no requests are sent to it. */
export const MONITORED_ASSET = 'gasha-cve-sentinel.vercel.app';
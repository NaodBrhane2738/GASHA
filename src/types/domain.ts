export type NodeKind =
  | 'compute'
  | 'database'
  | 'storage'
  | 'network'
  | 'identity'
  | 'endpoint'
  | 'external';

export type Exposure = 'public' | 'internal' | 'private';
export type Provider = 'vercel' | 'aws' | 'azure' | 'gcp' | 'onprem';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface TwinNode {
  id: string;
  kind: NodeKind;
  label: string;
  provider: Provider;
  criticality: 1 | 2 | 3 | 4 | 5;
  exposure: Exposure;
  riskScore: number;
  isCrownJewel?: boolean;
  metadata?: Record<string, unknown>;
}

export interface TwinEdge {
  id: string;
  source: string;
  target: string;
  relation: 'network' | 'iam' | 'data' | 'deploy' | 'depends';
  exploitable: boolean;
}

export interface TwinGraphData {
  nodes: TwinNode[];
  edges: TwinEdge[];
  updatedAt: string;
}

export interface AttackPath {
  id: string;
  entryNodeId: string;
  crownJewelNodeId: string;
  nodeIds: string[];
  edgeIds: string[];
  likelihood: number;
  impact: number;
  riskScore: number;
  techniques: string[];
  status: 'open' | 'mitigated' | 'accepted';
}

export interface TelemetryEvent {
  id: string;
  ts: string;
  nodeId: string;
  kind: 'process' | 'network' | 'auth' | 'file' | 'registry' | 'dns';
  summary: string;
  raw: Record<string, unknown>;
}

export interface DetectionRule {
  ruleId: string;
  name: string;
  description?: string;
  severity?: string;
  confidence?: number;
}

export interface Detection {
  id: string;
  ts: string;
  nodeId: string;
  rule: string | DetectionRule;
  severity: Severity;
  technique: string;
  confidence: number;
  summary: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: 'open' | 'contained' | 'resolved';
  openedAt: string;
  detectionIds: string[];
  pathId?: string;
  riskBefore: number;
  riskAfter?: number;
  confidence: number;
}

export type StoryEventKind =
  | 'initial-access'
  | 'execution'
  | 'persistence'
  | 'privilege-escalation'
  | 'lateral-movement'
  | 'collection'
  | 'exfiltration'
  | 'impact'
  | 'response';

export interface StoryEvent {
  id: string;
  ts: string;
  kind: StoryEventKind;
  nodeId: string;
  technique: string;
  narrative: string;
  evidenceIds: string[];
  inferred: boolean;
}

export type ResponseKind =
  | 'isolate-host'
  | 'revoke-credential'
  | 'block-ip'
  | 'rotate-secret'
  | 'disable-route';

export interface BlastRadius {
  nodeIds: string[];
  servicesAffected: string[];
  estimatedDowntime?: string;
}

export interface ResponseAction {
  id: string;
  incidentId: string;
  kind: ResponseKind;
  target: string;
  requiresApproval: boolean;
  state: 'proposed' | 'approved' | 'executing' | 'done' | 'failed' | 'rejected';
  blastRadius: BlastRadius;
  riskReduction?: number;
}

export interface RiskSnapshot {
  ts: string;
  score: number;
  openPaths: number;
  openIncidents: number;
}
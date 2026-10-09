/**
 * ==============================================================================
 * FILE: packages/contracts/entities/index.ts
 * ROLE / OWNERSHIP: Cross-Team Shared Contracts
 * OBJECTIVE: Define core domain entity models used across the GASHA platform.
 * TOOLS & LIBRARIES: TypeScript 5.x
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - Asset: Represents discovered infrastructure nodes (services, DBs, functions, repos).
 *   - Relationship: Directed edges connecting assets (CALLS, CONNECTS_TO, AUTHENTICATES_WITH).
 *   - Vulnerability: Static exposure and security misconfiguration findings.
 *   - RiskScore: Quantitative 0-100 risk scoring with contributor breakdowns.
 *   - AttackPath: High-probability traversal routes from entry points to critical assets.
 *   - Incident: Grouped security detections with status, timeline, and affected assets.
 *   - Evidence: Verified telemetry/detection items with cryptographic/temporal integrity.
 *   - InvestigationContext & Result: Grounded deterministic investigation context and attack narratives.
 *   - EnvironmentState: Global platform containment mode (NORMAL, ACTIVE_DEFENSE, LOCKDOWN).
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Single source of truth for frontend rendering, backend persistence, and deterministic analysis.
 * ==============================================================================
 */

export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type AssetCriticality = 'TIER_0_CROWN_JEWEL' | 'TIER_1_HIGH' | 'TIER_2_MEDIUM' | 'TIER_3_LOW';

export type AssetType = 
  | 'SERVICE'
  | 'DATABASE'
  | 'API_ENDPOINT'
  | 'LAMBDA_FUNCTION'
  | 'VERCEL_DEPLOYMENT'
  | 'GITHUB_REPOSITORY'
  | 'SECRET_STORE'
  | 'IDENTITY_ROLE'
  | 'STORAGE_BUCKET';

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  criticality: AssetCriticality;
  environmentId: string;
  source: 'VERCEL' | 'GITHUB' | 'TELEMETRY' | 'STATIC_CONFIG';
  metadata: Record<string, unknown>;
  isPubliclyExposed: boolean;
  status: 'ACTIVE' | 'DEGRADED' | 'ISOLATED' | 'INACTIVE';
  createdAt: string;
  updatedAt: string;
}

export type RelationshipType = 
  | 'CALLS'
  | 'CONNECTS_TO'
  | 'AUTHENTICATES_WITH'
  | 'HOSTS'
  | 'READS_FROM'
  | 'WRITES_TO'
  | 'DEPLOYS'
  | 'DEPENDS_ON';

export interface Relationship {
  id: string;
  sourceAssetId: string;
  targetAssetId: string;
  type: RelationshipType;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface Vulnerability {
  id: string;
  assetId: string;
  cveId?: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  cvssScore?: number;
  category: 
    | 'PUBLIC_EXPOSURE'
    | 'AUTH_WEAKNESS'
    | 'AUTHZ_WEAKNESS'
    | 'INSECURE_CONFIG'
    | 'VULNERABLE_DEPENDENCY'
    | 'SENSITIVE_DATA_EXPOSURE'
    | 'INJECTION_FLAW';
  remediationGuidance: string;
  status: 'OPEN' | 'MITIGATED' | 'SUPPRESSED';
  discoveredAt: string;
}

export interface RiskContributor {
  factor: string;
  weight: number;
  description: string;
}

export interface RiskScore {
  overallScore: number; // 0 - 100
  criticalAssetsAtRiskCount: number;
  highRiskVulnerabilitiesCount: number;
  activeAttackPathsCount: number;
  contributors: RiskContributor[];
  calculatedAt: string;
}

export interface RiskHistoryEntry {
  timestamp: string;
  score: number;
  triggerEvent: string;
}

export interface AttackPathNode {
  assetId: string;
  assetName: string;
  assetType: AssetType;
  stepOrder: number;
  vulnerabilityIds?: string[];
  description: string;
}

export interface AttackPath {
  id: string;
  entryPointAssetId: string;
  targetAssetId: string;
  severity: SeverityLevel;
  pathScore: number; // 0 - 100
  nodes: AttackPathNode[];
  isActive: boolean;
  discoveredAt: string;
  mitigatedAt?: string;
}

export type IncidentStatus = 'ACTIVE' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';

export interface Incident {
  id: string;
  title: string;
  severity: SeverityLevel;
  status: IncidentStatus;
  primaryAffectedAssetId: string;
  relatedAssetIds: string[];
  detectionEventIds: string[];
  attackPathId?: string;
  createdAt: string;
  updatedAt: string;
  summary?: string;
}

export type EvidenceType = 
  | 'TELEMETRY_EVENT'
  | 'DETECTION_MATCH'
  | 'NETWORK_LOG'
  | 'GRAPH_RELATIONSHIP'
  | 'CONFIG_DIFF';

export interface Evidence {
  id: string;
  type: EvidenceType;
  source: string;
  timestamp: string;
  content: Record<string, unknown>;
  relevanceExplanation: string;
  verified: boolean;
}

export interface Recommendation {
  id: string;
  actionType: 'BLOCK_SOURCE' | 'DISABLE_SESSION' | 'ISOLATE_RESOURCE';
  targetIdentifier: string;
  targetType: 'IP_ADDRESS' | 'USER_SESSION' | 'ASSET_ID';
  rationale: string;
  confidence: number; // 0.0 - 1.0
  expectedImpact: string;
}

export interface AttackStory {
  observedFacts: string[];
  reasonableInferences: string[];
  unknownsAndGaps: string[];
  narrativeSummary: string;
}

export interface InvestigationResult {
  incidentId: string;
  summary: string;
  severity: SeverityLevel;
  confidenceScore: number; // 0.0 - 1.0
  attackStory: AttackStory;
  groundedEvidence: Evidence[];
  recommendations: Recommendation[];
  generatedAt: string;
}

export interface InvestigationContext {
  incidentId: string;
  incident: Incident;
  timeline: Array<{
    timestamp: string;
    description: string;
    evidenceId: string;
  }>;
  affectedAssets: Asset[];
  relatedVulnerabilities: Vulnerability[];
  activeAttackPaths: AttackPath[];
  rawEvidence: Evidence[];
}

export interface EnvironmentState {
  id: string;
  name: string;
  syncedAt: string;
  totalAssets: number;
  activeIncidentsCount: number;
  currentRiskScore: number;
  containmentMode: 'NORMAL' | 'ACTIVE_DEFENSE' | 'LOCKDOWN';
}

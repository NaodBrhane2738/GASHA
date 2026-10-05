"""
==============================================================================
FILE: apps/api/app/ai/contracts.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Typed Pydantic v2 input and output contracts for the GASHA AI layer.
TOOLS & LIBRARIES: Pydantic v2
KEY FEATURES:
  - InvestigationContext: The strict, grounded input schema supplied to the AI.
  - AIInvestigationResult: The structured, verifiable output schema returned by the AI.
  - Epistemic classification models: ObservedFact, Inference, Unknown, AttackProgressionItem.
  - AIRecommendation: Allowlist-constrained defensive action proposals.
  - AIConfidenceAssessment: Structured confidence, rationale, and uncertainty metrics.
EXPECTED RESULTS / BEHAVIOR:
  - Provides a single, provider-independent contract boundary between GASHA's
    deterministic security pipeline and future LLM investigation reasoning engines.
==============================================================================
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Literal, Set
from pydantic import BaseModel, Field, ConfigDict

# Canonical types aligned with backend schemas
SeverityLevel = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
IncidentStatusType = Literal['ACTIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED']
ResponseActionType = Literal['BLOCK_SOURCE', 'DISABLE_SESSION', 'ISOLATE_RESOURCE']
ResponseTargetType = Literal['IP_ADDRESS', 'USER_SESSION', 'SESSION_ID', 'ASSET_ID']
EvidenceType = Literal[
    'TELEMETRY_EVENT',
    'DETECTION_MATCH',
    'NETWORK_LOG',
    'GRAPH_RELATIONSHIP',
    'CONFIG_DIFF',
    'VULNERABILITY_FINDING'
]
AIInvestigationStatus = Literal[
    'SUCCESS',
    'COMPLETED',
    'INSUFFICIENT_EVIDENCE',
    'INVALID',
    'INVALID_OUTPUT',
    'UNAVAILABLE',
    'TIMEOUT',
    'FALLBACK',
    'READY',
    'PROCESSING'
]

CompromiseAssessmentType = Literal[
    'CONFIRMED',
    'SUSPECTED',
    'ATTEMPT_ONLY',
    'NOT_ESTABLISHED',
    'UNKNOWN'
]

AttributionAssessmentType = Literal[
    'ESTABLISHED',
    'CONSISTENT_WITH_THREAT',
    'UNCONFIRMED',
    'UNKNOWN'
]

ALLOWED_RESPONSE_ACTIONS: Set[str] = {'BLOCK_SOURCE', 'DISABLE_SESSION', 'ISOLATE_RESOURCE'}
ALLOWED_ACTION_TARGET_MAP: Dict[ResponseActionType, Set[ResponseTargetType]] = {
    'BLOCK_SOURCE': {'IP_ADDRESS'},
    'DISABLE_SESSION': {'USER_SESSION', 'SESSION_ID'},
    'ISOLATE_RESOURCE': {'ASSET_ID'}
}

# Context contract versions
CURRENT_CONTEXT_VERSION: str = "1.0.0"
SUPPORTED_CONTEXT_VERSIONS: Set[str] = {"1.0.0", "1.0", "1.0-mvp"}



# ============================================================================
# 1. INPUT CONTRACTS (What GASHA Provides to the AI)
# ============================================================================

class EvidenceItem(BaseModel):
    """Individual unit of verifiable forensic evidence supplied to the AI."""
    id: str = Field(..., description="Unique evidence ID (e.g. EV-001, TEL-9821)")
    type: EvidenceType = Field(..., description="Category of forensic evidence")
    source: str = Field(..., description="Originating service, probe, or engine")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of occurrence")
    summary: str = Field(..., description="Concise human-readable description of the evidence")
    content: Dict[str, Any] = Field(default_factory=dict, description="Structured raw data payload")
    verified: bool = Field(default=True, description="Whether this evidence is cryptographically/deterministically verified")

    model_config = ConfigDict(extra="forbid")


class TelemetryEventContext(BaseModel):
    """Contextual representation of a relevant telemetry event."""
    id: str
    eventType: str
    timestamp: str
    sourceService: str
    environmentId: Optional[str] = None
    sourceIp: Optional[str] = None
    userAgent: Optional[str] = None
    userId: Optional[str] = None
    sessionId: Optional[str] = None
    httpMethod: Optional[str] = None
    httpPath: Optional[str] = None
    httpStatusCode: Optional[int] = None
    resourceAccessed: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class DetectionContext(BaseModel):
    """Contextual summary of a rule-based detection event."""
    id: str
    ruleId: str
    ruleName: str
    description: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0)
    matchedEventIds: List[str] = Field(default_factory=list)
    primaryAssetId: Optional[str] = None
    timestamp: str
    evidenceSummary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class AssetContext(BaseModel):
    """Contextual metadata of an asset involved in the investigation."""
    id: str
    name: str
    type: str
    criticality: str = "TIER_2_MEDIUM"
    isPubliclyExposed: bool = False
    environmentId: Optional[str] = None
    status: str = "ACTIVE"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class AttackPathHopContext(BaseModel):
    """Step along a graph-computed attack path."""
    stepOrder: int
    assetId: str
    assetName: str
    assetType: str
    description: str
    vulnerabilityIds: Optional[List[str]] = None

    model_config = ConfigDict(extra="ignore")


class AttackPathContext(BaseModel):
    """Graph-calculated attack path relevant to the incident."""
    id: str
    entryPointAssetId: str
    targetAssetId: str
    severity: SeverityLevel
    pathScore: float
    nodes: List[AttackPathHopContext] = Field(default_factory=list)
    isActive: bool = True

    model_config = ConfigDict(extra="ignore")


class VulnerabilityContext(BaseModel):
    """Vulnerability or security finding associated with involved assets."""
    id: str
    cveId: Optional[str] = None
    assetId: str
    title: str
    severity: SeverityLevel
    description: str
    cvssScore: Optional[float] = None

    model_config = ConfigDict(extra="ignore")


class RiskContext(BaseModel):
    """Quantitative risk snapshot at time of investigation."""
    overallScore: float = Field(ge=0.0, le=100.0)
    criticalAssetsAtRiskCount: int = 0
    highRiskVulnerabilitiesCount: int = 0
    activeAttackPathsCount: int = 0
    primaryRiskDrivers: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class IncidentContext(BaseModel):
    """Correlated security incident metadata."""
    id: str
    title: str
    severity: SeverityLevel
    status: IncidentStatusType
    primaryAffectedAssetId: str
    relatedAssetIds: List[str] = Field(default_factory=list)
    detectionEventIds: List[str] = Field(default_factory=list)
    attackPathId: Optional[str] = None
    createdAt: str
    updatedAt: str
    summary: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class AvailableActionContext(BaseModel):
    """Defines an allowlisted response action available for execution."""
    actionType: ResponseActionType
    allowedTargetTypes: List[ResponseTargetType]
    description: str
    requiresApproval: bool = True

    model_config = ConfigDict(extra="forbid")


class InvestigationContext(BaseModel):
    """
    Authoritative, closed-world input bundle provided by GASHA to the AI.
    Every claim made by the AI MUST trace back to elements within this context.
    """
    incident: IncidentContext
    evidence: List[EvidenceItem] = Field(
        default_factory=list,
        description="All verifiable evidence items associated with this investigation"
    )
    detections: List[DetectionContext] = Field(
        default_factory=list,
        description="Deterministic detection rule triggers"
    )
    telemetryEvents: List[TelemetryEventContext] = Field(
        default_factory=list,
        description="Relevant filtered telemetry events"
    )
    assets: List[AssetContext] = Field(
        default_factory=list,
        description="Metadata of involved infrastructure assets"
    )
    attackPath: Optional[AttackPathContext] = Field(
        default=None,
        description="Current graph traversal attack path if available"
    )
    vulnerabilities: List[VulnerabilityContext] = Field(
        default_factory=list,
        description="Relevant known vulnerabilities on affected assets"
    )
    riskSnapshot: Optional[RiskContext] = Field(
        default=None,
        description="Risk score breakdown at investigation time"
    )
    availableResponseActions: List[AvailableActionContext] = Field(
        default_factory=lambda: [
            AvailableActionContext(
                actionType="BLOCK_SOURCE",
                allowedTargetTypes=["IP_ADDRESS"],
                description="Block incoming traffic from a malicious external IP address",
                requiresApproval=True
            ),
            AvailableActionContext(
                actionType="DISABLE_SESSION",
                allowedTargetTypes=["USER_SESSION", "SESSION_ID"],
                description="Revoke an active compromised user authentication session",
                requiresApproval=True
            ),
            AvailableActionContext(
                actionType="ISOLATE_RESOURCE",
                allowedTargetTypes=["ASSET_ID"],
                description="Sever network egress and ingress for a compromised asset",
                requiresApproval=True
            )
        ],
        description="Strict allowlist of response capabilities currently enabled in GASHA"
    )
    assembledAt: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of context assembly"
    )
    contextVersion: str = Field(
        default=CURRENT_CONTEXT_VERSION,
        description="Schema version of this InvestigationContext contract (e.g. '1.0.0')"
    )

    model_config = ConfigDict(extra="forbid")

    def get_all_evidence_ids(self) -> Set[str]:
        """Returns the complete set of valid evidence IDs available for citation."""
        ids = {e.id for e in self.evidence}
        for d in self.detections:
            ids.add(d.id)
            ids.update(d.matchedEventIds)
        for t in self.telemetryEvents:
            ids.add(t.id)
        return ids

    def get_all_asset_ids(self) -> Set[str]:
        """Returns the set of all valid asset IDs present in context."""
        ids = {a.id for a in self.assets}
        ids.add(self.incident.primaryAffectedAssetId)
        ids.update(self.incident.relatedAssetIds)
        if self.attackPath:
            ids.add(self.attackPath.entryPointAssetId)
            ids.add(self.attackPath.targetAssetId)
            for node in self.attackPath.nodes:
                ids.add(node.assetId)
        return ids

    def get_all_known_ips(self) -> Set[str]:
        """Returns all IP addresses explicitly present in context evidence and telemetry."""
        ips: Set[str] = set()
        for e in self.evidence:
            if isinstance(e.content, dict):
                for k in ("ip", "sourceIp", "matchedIp", "clientIp", "remoteIp", "destinationIp"):
                    if e.content.get(k):
                        ips.add(str(e.content[k]))
            # Also extract IP patterns from summary
            if hasattr(e, "summary") and e.summary:
                import re
                for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", e.summary):
                    ips.add(match)
        for t in self.telemetryEvents:
            if t.sourceIp:
                ips.add(t.sourceIp)
        for d in self.detections:
            if hasattr(d, "evidenceSummary") and d.evidenceSummary:
                import re
                for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", d.evidenceSummary):
                    ips.add(match)
        return ips

    def get_all_known_sessions(self) -> Set[str]:
        """Returns all session identifiers explicitly present in context."""
        sessions: Set[str] = set()
        for e in self.evidence:
            if isinstance(e.content, dict):
                for k in ("sessionId", "session", "token", "session_id", "authSession"):
                    if e.content.get(k):
                        sessions.add(str(e.content[k]))
        for t in self.telemetryEvents:
            if t.sessionId:
                sessions.add(t.sessionId)
        return sessions

    def get_all_known_users(self) -> Set[str]:
        """Returns all usernames / user IDs explicitly present in context."""
        users: Set[str] = set()
        for e in self.evidence:
            if isinstance(e.content, dict):
                for k in ("user", "userId", "username", "account", "user_id", "principal"):
                    if e.content.get(k):
                        users.add(str(e.content[k]))
        for t in self.telemetryEvents:
            if t.userId:
                users.add(t.userId)
        return users

    def get_evidence_type_map(self) -> Dict[str, str]:
        """Maps all evidence IDs to their explicit evidence category."""
        type_map: Dict[str, str] = {}
        for e in self.evidence:
            type_map[e.id] = e.type
        for d in self.detections:
            type_map[d.id] = "DETECTION_MATCH"
            for mid in d.matchedEventIds:
                if mid not in type_map:
                    type_map[mid] = "TELEMETRY_EVENT"
        for t in self.telemetryEvents:
            type_map[t.id] = "TELEMETRY_EVENT"
        return type_map



# ============================================================================
# 2. OUTPUT CONTRACTS (What the AI Must Return)
# ============================================================================

class ObservedFact(BaseModel):
    """
    A concrete fact directly verified by one or more supplied evidence items.
    Must NOT contain speculation or deductions.
    """
    statement: str = Field(..., description="Factual description directly grounded in evidence")
    evidenceIds: List[str] = Field(
        ...,
        min_length=1,
        description="IDs of the evidence items that directly prove this fact"
    )

    model_config = ConfigDict(extra="forbid")


class Inference(BaseModel):
    """
    A logical deduction derived from observed facts.
    Must be explicitly separated from direct facts.
    """
    statement: str = Field(..., description="Deductive conclusion or hypothesis")
    rationale: str = Field(..., description="Explanation of why this inference follows from facts")
    supportingEvidenceIds: List[str] = Field(
        default_factory=list,
        description="Supporting evidence IDs grounding this inference"
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Estimated certainty of this inference"
    )

    model_config = ConfigDict(extra="forbid")


class Unknown(BaseModel):
    """
    An explicit statement of missing information, unobserved telemetry, or investigation gaps.
    """
    statement: str = Field(..., description="Description of the information gap or unknown aspect")
    significance: Optional[str] = Field(
        default=None,
        description="Why this unknown matters for the security assessment"
    )
    recommendedTelemetry: Optional[str] = Field(
        default=None,
        description="What log source or probe would resolve this unknown"
    )

    model_config = ConfigDict(extra="forbid")


class AttackProgressionItem(BaseModel):
    """
    A chronological step in the reconstructed attack story.
    """
    stepOrder: int = Field(..., ge=1, description="Sequential ordering of this attack step")
    phase: str = Field(..., description="MITRE ATT&CK or kill-chain phase (e.g. Initial Access, Discovery, Impact)")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp if established by telemetry")
    sourceEntity: Optional[str] = Field(default=None, description="Attacker IP, compromised account, or originating node")
    targetAssetId: Optional[str] = Field(default=None, description="Targeted asset or service ID")
    description: str = Field(..., description="Clear explanation of the activity during this step")
    isAttemptOnly: bool = Field(
        default=False,
        description="True if the action was an unfulfilled attempt (e.g. 403 Forbidden, auth failure)"
    )
    evidenceIds: List[str] = Field(
        default_factory=list,
        description="Evidence IDs directly supporting this step"
    )

    model_config = ConfigDict(extra="forbid")

    @property
    def stepNumber(self) -> int:
        """Ergonomic alias for stepOrder."""
        return self.stepOrder

    @property
    def assetId(self) -> Optional[str]:
        """Ergonomic alias for targetAssetId."""
        return self.targetAssetId

    @property
    def techniqueName(self) -> Optional[str]:
        """Technique alias placeholder."""
        return None



class AIRecommendation(BaseModel):
    """
    An allowlist-constrained defensive action recommendation.
    Must NOT contain executable scripts or non-allowlisted actions.
    """
    id: str = Field(..., description="Unique recommendation ID (e.g. rec-1)")
    actionType: ResponseActionType = Field(
        ...,
        description="Allowlisted action: BLOCK_SOURCE, DISABLE_SESSION, or ISOLATE_RESOURCE"
    )
    targetIdentifier: str = Field(
        ...,
        description="Specific entity to target (e.g. IP address, Session ID, or Asset ID)"
    )
    targetType: ResponseTargetType = Field(
        ...,
        description="Entity type: IP_ADDRESS, USER_SESSION, SESSION_ID, or ASSET_ID"
    )
    rationale: str = Field(
        ...,
        description="Grounded justification explaining why this action is required"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in this recommendation (0.0 to 1.0)"
    )
    expectedImpact: str = Field(
        ...,
        description="Anticipated security and operational containment effect"
    )
    supportingEvidenceIds: List[str] = Field(
        default_factory=list,
        description="Evidence IDs justifying this recommendation"
    )
    priority: Optional[Literal['IMMEDIATE', 'HIGH', 'MEDIUM', 'LOW']] = Field(
        default='HIGH',
        description="Operational urgency of the proposed recommendation"
    )

    model_config = ConfigDict(extra="forbid")

    @property
    def target(self) -> str:
        """Ergonomic alias for targetIdentifier."""
        return self.targetIdentifier

    @property
    def requireManualApproval(self) -> bool:
        """Always True: all AI recommendations strictly require human analyst authorization."""
        return True

    @property
    def requestedBy(self) -> str:
        """Always ANALYST_MANUAL for human-in-the-loop response governance."""
        return "ANALYST_MANUAL"

    @property
    def action(self) -> str:
        """Ergonomic alias for actionType."""
        return str(self.actionType)



class ConfidenceAssessment(BaseModel):
    """
    Nuanced uncertainty and confidence assessment of the AI investigation.
    """
    score: float = Field(ge=0.0, le=1.0, description="Overall confidence score (0.0 to 1.0)")
    rationale: str = Field(..., description="Justification for the assigned score based on evidence density")
    evidenceCompleteness: Literal['HIGH', 'MODERATE', 'LOW', 'INSUFFICIENT'] = Field(
        default='MODERATE',
        description="Subjective rating of telemetry coverage for this incident"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Known constraints, missing visibility, or ambiguities in the analysis"
    )

    model_config = ConfigDict(extra="forbid")


class AIInvestigationResult(BaseModel):
    """
    The complete, strictly validated structured result emitted by the AI layer.
    """
    incidentId: str = Field(..., description="ID of the investigated incident")
    status: AIInvestigationStatus = Field(
        default='SUCCESS',
        description="Outcome of the AI investigation analysis"
    )
    summary: str = Field(
        ...,
        description="Concise, executive-level summary of the incident investigation"
    )
    severity: SeverityLevel = Field(
        ...,
        description="AI-assessed incident severity based strictly on grounded evidence"
    )
    confidence: ConfidenceAssessment = Field(
        ...,
        description="Comprehensive confidence assessment with uncertainty metrics"
    )
    observedFacts: List[ObservedFact] = Field(
        default_factory=list,
        description="Facts directly confirmed by supplied evidence items"
    )
    inferences: List[Inference] = Field(
        default_factory=list,
        description="Reasonable deductions derived from observed facts"
    )
    unknowns: List[Unknown] = Field(
        default_factory=list,
        description="Explicitly identified telemetry gaps or unconfirmed aspects"
    )
    attackProgression: List[AttackProgressionItem] = Field(
        default_factory=list,
        description="Chronological step-by-step reconstruction of the attack story"
    )
    affectedAssetIds: List[str] = Field(
        default_factory=list,
        description="List of verified asset IDs impacted by the incident"
    )
    citedEvidenceIds: List[str] = Field(
        default_factory=list,
        description="De-duplicated list of all evidence IDs referenced in the result"
    )
    recommendedActions: List[AIRecommendation] = Field(
        default_factory=list,
        description="Strictly allowlisted containment recommendations"
    )
    generatedAt: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of investigation generation"
    )
    errorMessage: Optional[str] = Field(
        default=None,
        description="Details populated only if status is INVALID or UNAVAILABLE"
    )
    compromiseAssessment: CompromiseAssessmentType = Field(
        default='NOT_ESTABLISHED',
        description="Deterministic assessment of whether compromise was achieved vs unfulfilled attempt"
    )
    attributionAssessment: AttributionAssessmentType = Field(
        default='UNCONFIRMED',
        description="Assessment of whether specific threat actor attribution is established"
    )

    model_config = ConfigDict(extra="forbid")

    @property
    def isFallback(self) -> bool:
        """Convenience property indicating if this result came from a deterministic fallback."""
        return self.status in ("FALLBACK", "UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "INVALID")

    @property
    def is_fallback(self) -> bool:
        """Snake_case alias for isFallback."""
        return self.isFallback

    @property
    def isSuccess(self) -> bool:
        """Convenience property indicating successful model investigation."""
        return self.status in ("SUCCESS", "COMPLETED")

    @property
    def is_success(self) -> bool:
        """Snake_case alias for isSuccess."""
        return self.isSuccess

    @property
    def isUnavailable(self) -> bool:
        """Convenience property indicating provider offline or timed out."""
        return self.status in ("UNAVAILABLE", "TIMEOUT")

    @property
    def is_unavailable(self) -> bool:
        """Snake_case alias for isUnavailable."""
        return self.isUnavailable

    def collect_all_cited_evidence_ids(self) -> Set[str]:
        """Aggregates all evidence IDs cited anywhere across facts, inferences, progression, and recs."""
        cited: Set[str] = set(self.citedEvidenceIds)
        for fact in self.observedFacts:
            cited.update(fact.evidenceIds)
        for inf in self.inferences:
            cited.update(inf.supportingEvidenceIds)
        for step in self.attackProgression:
            cited.update(step.evidenceIds)
        for rec in self.recommendedActions:
            cited.update(rec.supportingEvidenceIds)
        return cited


class AttackStoryStage(BaseModel):
    """
    A discrete, chronologically ordered stage in the attack narrative.
    """
    order: int = Field(..., ge=1, description="Sequential stage order (1-indexed)")
    timestamp: Optional[str] = Field(
        default=None,
        description="ISO timestamp or time range if established by telemetry"
    )
    phase: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK or kill-chain stage classification"
    )
    description: str = Field(
        ...,
        description="Clear, technically accurate explanation of observed activity"
    )
    affectedAssetIds: List[str] = Field(
        default_factory=list,
        description="Assets involved in or affected by this stage"
    )
    evidenceIds: List[str] = Field(
        default_factory=list,
        description="Grounded evidence IDs supporting this stage"
    )
    isAttemptOnly: bool = Field(
        default=False,
        description="True if this stage represents an unsuccessful or blocked attempt"
    )

    model_config = ConfigDict(extra="forbid")


class AttackStory(BaseModel):
    """
    The human-readable, evidence-grounded security narrative of what occurred during the incident.
    """
    incidentId: str = Field(..., description="ID of the investigated incident")
    title: str = Field(..., description="Concise, informative title of the incident narrative")
    summary: str = Field(..., description="Executive-level narrative summarizing the attack story")
    severity: SeverityLevel = Field(..., description="Assessed severity level")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall confidence score in this attack story"
    )
    stages: List[AttackStoryStage] = Field(
        default_factory=list,
        description="Chronologically ordered stages of the attack"
    )
    observedFacts: List[ObservedFact] = Field(
        default_factory=list,
        description="Concrete, verified facts directly proven by evidence"
    )
    inferences: List[Inference] = Field(
        default_factory=list,
        description="Reasonable deductions derived logically from observed facts"
    )
    unknowns: List[Unknown] = Field(
        default_factory=list,
        description="Explicitly identified telemetry gaps or unconfirmed aspects"
    )
    uncertainty: str = Field(
        ...,
        description="Explicit statement of unconfirmed aspects, missing proof, or gaps"
    )
    affectedAssetIds: List[str] = Field(
        default_factory=list,
        description="All asset IDs involved in the story"
    )
    citedEvidenceIds: List[str] = Field(
        default_factory=list,
        description="All evidence IDs cited across story stages"
    )
    generatedAt: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of story generation"
    )
    compromiseAssessment: CompromiseAssessmentType = Field(
        default='NOT_ESTABLISHED',
        description="Deterministic assessment of whether compromise was achieved"
    )
    attributionAssessment: AttributionAssessmentType = Field(
        default='UNCONFIRMED',
        description="Assessment of whether threat actor attribution is established"
    )

    model_config = ConfigDict(extra="forbid")


# ============================================================================
# 3. INTEGRATION & VERSIONING CONTRACTS (Backend Handoff)
# ============================================================================

def calculate_context_fingerprint(context: InvestigationContext) -> str:
    """
    Computes a deterministic, collision-resistant SHA-256 fingerprint of the InvestigationContext.
    Used by Backend and AI pipeline to detect context drift, new evidence, and ensure idempotency.
    """
    canonical_data = {
        "incidentId": context.incident.id if context.incident else "",
        "incidentUpdatedAt": context.incident.updatedAt if context.incident else "",
        "incidentSeverity": context.incident.severity if context.incident else "",
        "contextVersion": getattr(context, "contextVersion", CURRENT_CONTEXT_VERSION),
        "evidenceIds": sorted([e.id for e in context.evidence]),
        "detectionIds": sorted([d.id for d in context.detections]),
        "telemetryIds": sorted([t.id for t in context.telemetryEvents]),
        "assetIds": sorted([a.id for a in context.assets]),
        "attackPathId": context.attackPath.id if context.attackPath else None,
        "vulnerabilityIds": sorted([v.id for v in context.vulnerabilities]),
        "riskScore": context.riskSnapshot.overallScore if context.riskSnapshot else None,
    }
    encoded = json.dumps(canonical_data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class AIInvestigationEnvelope(BaseModel):
    """
    A versioned, traceable envelope encapsulating an AI investigation run for backend consumption.
    Links the investigation outcome directly to the specific context version and model used.
    """
    investigationId: str = Field(
        default_factory=lambda: f"inv-{uuid.uuid4().hex[:12]}",
        description="Unique execution ID for this investigation run"
    )
    incidentId: str = Field(..., description="ID of the investigated incident")
    contextFingerprint: str = Field(
        ...,
        description="Deterministic SHA-256 fingerprint of the InvestigationContext at run time"
    )
    model: str = Field(..., description="Identifier of the AI model or engine used")
    status: AIInvestigationStatus = Field(..., description="Investigation status classification")
    isFallback: bool = Field(default=False, description="True if deterministic fallback was returned")
    result: AIInvestigationResult = Field(..., description="Full structured investigation result")
    attackStory: Optional[AttackStory] = Field(
        default=None,
        description="Structured, evidence-grounded attack story if generated"
    )
    recommendations: List[AIRecommendation] = Field(
        default_factory=list,
        description="Allowlisted advisory recommendations for human review"
    )
    generatedAt: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of investigation execution"
    )
    executionDurationMs: Optional[float] = Field(
        default=None,
        description="Total execution wall-clock time in milliseconds"
    )

    model_config = ConfigDict(extra="forbid")

    @property
    def is_fallback(self) -> bool:
        """Snake_case alias for isFallback."""
        return self.isFallback

    @property
    def isSuccess(self) -> bool:
        """Convenience property indicating successful model investigation."""
        return self.status in ("SUCCESS", "COMPLETED")

    @property
    def is_success(self) -> bool:
        """Snake_case alias for isSuccess."""
        return self.isSuccess



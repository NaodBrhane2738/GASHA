"""
==============================================================================
FILE: apps/api/app/schemas/soc.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Typed contracts for the SOC monitoring pipeline (findings, policy decisions,
           mitigations, incident lifecycle, telemetry metrics, remediation guidance).
TOOLS & LIBRARIES: Pydantic v2
EXPECTED RESULTS / BEHAVIOR:
  - Single shape shared by the detection engine, policy enforcer, event bus, REST API,
    SSE stream and the web dashboard (mirrored in apps/web/src/types/soc.ts).
==============================================================================
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_RANK: Dict[str, int] = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

FindingCategory = Literal[
    "RATE_LIMIT_EXCEEDED",
    "BRUTE_FORCE_AUTH",
    "MALFORMED_PAYLOAD",
    "OVERSIZED_PAYLOAD",
    "SQL_INJECTION",
    "PATH_TRAVERSAL",
    "XSS_PROBE",
]

FindingLocation = Literal["path", "query", "body", "header", "telemetry"]

# Defensive decisions the policy engine may take. THROTTLE -> HTTP 429, LOCK -> HTTP 423,
# REJECT -> HTTP 413/400 for a single request without penalising the source further.
PolicyAction = Literal["ALLOW", "FLAG", "THROTTLE", "LOCK", "REJECT"]

LifecycleStage = Literal["INGESTED", "DETECTED", "ENFORCED", "MITIGATED"]
IncidentStatus = Literal["OPEN", "MITIGATED", "RESOLVED"]


class Finding(BaseModel):
    """A single flagged observation with its root-cause diagnostic."""
    id: str
    ts: str
    sourceKey: str
    method: Optional[str] = None
    path: Optional[str] = None
    category: FindingCategory
    ruleId: str
    severity: Severity
    location: FindingLocation
    field: Optional[str] = None
    # Sanitised, truncated excerpt. Raw payloads are never stored.
    evidence: Optional[str] = None
    diagnostic: str
    incidentId: Optional[str] = None


class PolicyDecision(BaseModel):
    action: PolicyAction
    statusCode: int = 200
    ruleId: Optional[str] = None
    reason: Optional[str] = None
    severity: Severity = "LOW"
    retryAfterSeconds: Optional[int] = None
    sourceKey: str
    findingIds: List[str] = Field(default_factory=list)


class Mitigation(BaseModel):
    sourceKey: str
    action: Literal["THROTTLE", "LOCK"]
    ruleId: str
    reason: str
    severity: Severity
    createdAt: str
    expiresAt: str
    blockedRequests: int = 0


class LifecycleStep(BaseModel):
    stage: LifecycleStage
    at: str
    detail: str


class Incident(BaseModel):
    id: str
    sourceKey: str
    title: str
    severity: Severity
    status: IncidentStatus
    stage: LifecycleStage
    steps: List[LifecycleStep]
    findingIds: List[str] = Field(default_factory=list)
    mitigation: Optional[Mitigation] = None
    blockedRequests: int = 0
    openedAt: str
    updatedAt: str
    resolvedAt: Optional[str] = None


class MetricsBucket(BaseModel):
    ts: str
    total: int = 0
    allowed: int = 0
    flagged: int = 0
    throttled: int = 0
    locked: int = 0
    rejected: int = 0
    # Highest per-source request count inside the sliding window at this second.
    peakSourceRate: int = 0


class RateLimitPolicyView(BaseModel):
    limit: int
    windowSeconds: int
    escalationCount: int
    escalationWindowSeconds: int
    lockDurationSeconds: int


class SourceRate(BaseModel):
    sourceKey: str
    requestsInWindow: int


class MetricsSnapshot(BaseModel):
    series: List[MetricsBucket]
    policy: RateLimitPolicyView
    activeMitigations: List[Mitigation]
    topSources: List[SourceRate]
    totals: Dict[str, int]


class Recommendation(BaseModel):
    title: str
    detail: str
    snippet: Optional[str] = None
    snippetLanguage: Optional[str] = None
    reference: Optional[str] = None


class FindingAnalysis(BaseModel):
    finding: Finding
    rootCause: str
    impact: str
    recommendations: List[Recommendation]
    relatedFindings: List[Finding] = Field(default_factory=list)


class SocEvent(BaseModel):
    """Envelope published on the event bus and forwarded verbatim over SSE."""
    id: str
    type: Literal[
        "finding.created",
        "policy.enforced",
        "request.blocked",
        "mitigation.expired",
        "mitigation.released",
        "incident.updated",
        "alert.dispatched",
        "alert.failed",
        "metrics.tick",
    ]
    ts: str
    data: Dict[str, Any]

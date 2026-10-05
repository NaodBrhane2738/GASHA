# GASHA AI–Backend Integration Contract & Production Handoff

> **Module**: `apps/api/app/ai/`  
> **Target Audience**: Backend Engineers, Security Operations, API Developers  
> **Roadmap Step**: 6.8 (AI–Backend Integration Contract & Production Handoff)  
> **Status**: Verified & Production-Ready  

---

## 1. Overview & Service Boundary Architecture

The GASHA AI / Security Intelligence subsystem provides evidence-grounded, local-LLM-driven security investigation analysis, chronological attack stories, and allowlisted advisory mitigation proposals.

To ensure long-term stability, safety, and maintainability, the AI module is completely decoupled from the rest of the backend:

```
+-------------------------------------------------------------------------+
|                              BACKEND LAYER                              |
|                                                                         |
|   +---------------------+        +----------------------------------+   |
|   | Incident Triage API |        | Response Engine / Digital Twin   |   |
|   +----------+----------+        +-----------------+----------------+   |
+--------------|-------------------------------------|--------------------+
               | 1. InvestigationContext             | 5. Advisory Actions
               v                                     |    (Manual Approval)
+----------------------------------------------------+--------------------+
|                               AI LAYER                                  |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   | Public Integration Facade (app.ai.integration)                  |   |
|   | - calculate_context_fingerprint()                               |   |
|   | - run_ai_investigation()                                        |   |
|   | - map_to_backend_investigation_response()                       |   |
|   +--------------------------------+--------------------------------+   |
|                                    | 2. Execute Pipeline                |
|                                    v                                    |
|   +-----------------------------------------------------------------+   |
|   | Production Investigation Pipeline (app.ai.pipeline)             |   |
|   | - Local LLM Ingestion (Ollama)                                  |   |
|   | - Closed-World Evidence Grounding & Schema Validation           |   |
|   | - Attack Story Reconstructor & Allowlist Recommendation Engine  |   |
|   | - Safe Deterministic Fallback on Model Failure                  |   |
|   +--------------------------------+--------------------------------+   |
|                                    | 3. Returns Envelope                |
|                                    v                                    |
|   +-----------------------------------------------------------------+   |
|   | AIInvestigationEnvelope (Versioned, Traceable, Advisory-Only)   |   |
|   +-----------------------------------------------------------------+   |
+------------------------------------|------------------------------------+
                                     | 4. AIInvestigationEnvelope
                                     v
+-------------------------------------------------------------------------+
|                              BACKEND LAYER                              |
|   - Stores Investigation Result in DB / Memory Cache                    |
|   - Serves Investigation via GET /api/v1/investigations/{incident_id}   |
|   - Routes AI Recommendations to Analyst Approval Queue                 |
+-------------------------------------------------------------------------+
```

### The Caller Does NOT Need to Know:
- Which local LLM is configured (e.g. `qwen2.5-coder:7b`).
- How Ollama endpoints are queried or timed out.
- How prompts and delimiters are constructed or secured.
- How evidence IDs and assets are validated against hallucinations.
- How fallbacks are deterministically triggered.

---

## 2. What Backend Sends: Input Contract (`InvestigationContext`)

The Backend or Context Builder constructs an `InvestigationContext` (`app.ai.contracts:InvestigationContext`) from available incident data, telemetry, detections, assets, and attack paths.

```python
from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    AssetContext,
    AttackPathContext,
    VulnerabilityContext,
    RiskContext
)
```

### Key Fields of `InvestigationContext`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `incident` | `IncidentContext` | Correlated security incident metadata (`id`, `title`, `severity`, `status`, etc.). |
| `evidence` | `List[EvidenceItem]` | Verifiable forensic items (`id`, `type`, `source`, `timestamp`, `summary`, `content`, `verified`). |
| `detections` | `List[DetectionContext]` | Deterministic detection rule triggers with matched event IDs. |
| `telemetryEvents`| `List[TelemetryEventContext]` | Filtered, prioritized, and secret-scrubbed raw telemetry events. |
| `assets` | `List[AssetContext]` | Metadata of involved infrastructure assets (`id`, `name`, `type`, `criticality`). |
| `attackPath` | `Optional[AttackPathContext]` | Graph-calculated attack path hops if computed by the Digital Twin. |
| `vulnerabilities`| `List[VulnerabilityContext]` | Known CVEs and vulnerability findings on affected assets. |
| `riskSnapshot` | `Optional[RiskContext]` | Quantitative risk score breakdown at the time of investigation. |
| `availableResponseActions` | `List[AvailableActionContext]` | Allowlist of permitted actions (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`). |
| `assembledAt` | `str` (ISO 8601 UTC) | Timestamp of context generation. |

---

## 3. What AI Returns: Output Contract (`AIInvestigationEnvelope`)

The AI returns a versioned `AIInvestigationEnvelope` (`app.ai.contracts:AIInvestigationEnvelope`) containing the core investigation result, attack story, advisory recommendations, and execution metadata.

### Key Fields of `AIInvestigationEnvelope`:

```python
class AIInvestigationEnvelope(BaseModel):
    investigationId: str            # Unique execution ID (e.g., "inv-d4f1a8e29c01")
    incidentId: str                 # ID of the investigated incident
    contextFingerprint: str         # Deterministic SHA-256 fingerprint of the input context
    model: str                      # Model identifier used (e.g., "qwen2.5-coder:7b")
    status: AIInvestigationStatus   # Status classification (COMPLETED, FALLBACK, etc.)
    isFallback: bool                # True if deterministic fallback was triggered
    result: AIInvestigationResult   # Full structured investigation result
    attackStory: Optional[AttackStory]              # Grounded narrative and chronological timeline
    recommendations: List[AIRecommendation]        # Allowlist-bounded advisory actions
    generatedAt: str                # ISO 8601 UTC timestamp
    executionDurationMs: Optional[float]           # Wall-clock execution time in milliseconds
```

### Core Result Fields (`envelope.result`):
- `summary`: Concise executive summary of findings.
- `severity`: Assessed incident severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `confidence`: Structured confidence score (0.0–1.0), rationale, and limitations.
- `observedFacts`: List of facts directly grounded in evidence IDs (`statement`, `evidenceIds`).
- `inferences`: List of logical deductions separated from facts (`statement`, `rationale`, `supportingEvidenceIds`, `confidence`).
- `unknowns`: Explicitly flagged telemetry gaps or unconfirmed aspects (`statement`, `significance`, `recommendedTelemetry`).
- `attackProgression`: Chronological attack steps (`stepOrder`, `phase`, `description`, `isAttemptOnly`, `evidenceIds`).
- `affectedAssetIds`: Verified asset IDs impacted by the incident.
- `citedEvidenceIds`: Complete de-duplicated set of evidence IDs referenced in the result.

---

## 4. AI Status Lifecycle & Backend Handling

The AI layer categorizes all outcomes into explicit status states:

| Status Code | Meaning | Backend Operational Interpretation |
| :--- | :--- | :--- |
| `COMPLETED` / `SUCCESS` | Model completed investigation and passed all closed-world validation checks. | **Full AI Output Available**: Present full AI attack story, inferences, and recommendations to the analyst. |
| `INSUFFICIENT_EVIDENCE` | Context has zero or negligible evidence; AI cannot draw sound conclusions. | **Data Deficiency Warning**: Display uncertainty notice to analyst; retain deterministic incident data without AI inferences. |
| `FALLBACK` | Model produced malformed JSON, hallucinated citations, or non-allowlisted actions. | **Safe Fallback**: Present deterministic rule-based summary; clearly label that output is fallback analysis, not LLM reasoning. |
| `UNAVAILABLE` | Local LLM / Ollama instance is offline or unreachable. | **Provider Offline**: Display provider offline banner; do NOT block incident triage or mark incident as failed. |
| `TIMEOUT` | Model inference exceeded configured execution time budget (e.g. 30s). | **Analysis Timeout**: Present deterministic fallback; alert administrator to check local GPU/model workload. |
| `INVALID_OUTPUT` | Output failed JSON syntax parsing and could not be recovered. | **Malformed Output**: Automatically routed to deterministic fallback. |
| `READY` / `PROCESSING` | Investigation queued or currently executing in background. | **State Tracking**: Used for asynchronous job status reporting in polling/WebSocket interfaces. |

---

## 5. How Backend Invokes the AI Service

Backend components should consume the AI layer via `app.ai.integration`:

### Python Integration Example

```python
from app.ai.integration import (
    run_ai_investigation,
    map_to_backend_investigation_response,
    format_recommendation_for_backend,
    is_context_stale
)
from app.ai.context_builder import build_investigation_context

# 1. Build context from backend incident entities
context = build_investigation_context(
    incident=incident_record,
    detections=detection_records,
    telemetry_events=telemetry_records,
    assets=asset_records,
    attack_path=attack_path_record,
    vulnerabilities=vulnerability_records,
    risk_snapshot=risk_record
)

# 2. Execute investigation
envelope = await run_ai_investigation(context)

# 3. Store result envelope in database / cache
save_investigation_envelope(incident_id=incident_record.id, envelope=envelope)

# 4. Map to API response structure for FastAPI router
api_response = map_to_backend_investigation_response(envelope, context)
```

---

## 6. Idempotency, Staleness, and Repeat Investigations

To prevent redundant LLM inference while ensuring investigations stay up-to-date when new telemetry arrives:

1. **Context Fingerprinting**: `calculate_context_fingerprint(context)` produces a deterministic SHA-256 hash over the canonical state of the incident, evidence IDs, detection IDs, telemetry IDs, asset IDs, attack path ID, and risk score.
2. **Staleness Verification**: When an investigation is requested for an incident that already has an existing result, Backend can check:
   ```python
   if not is_context_stale(current_context, existing_envelope):
       return existing_envelope  # Context unchanged; return cached result instantly
   ```
3. **Traceability**: Every generated envelope records `contextFingerprint`, allowing analysts to verify exactly what evidence was known at the time the analysis was produced.

---

## 7. Recommendation Handoff & Response Safety

### Absolute Non-Execution Rule
> [!IMPORTANT]
> The AI layer **NEVER** executes containment or response actions autonomously. All AI proposals are strictly advisory recommendations requiring explicit human analyst authorization.

### Handoff Workflow
1. AI generates `AIRecommendation` objects (bounded strictly to `BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`).
2. Backend transforms recommendations into the standard `ResponseActionRequest` shape using:
   ```python
   action_payload = format_recommendation_for_backend(rec, incident_id="INC-001")
   ```
3. Backend displays the proposed action in the Analyst Triage UI with `requestedBy = 'ANALYST_MANUAL'`.
4. When the human analyst clicks **"Approve Action"**, the request is submitted to the existing Backend response endpoint:
   `POST /api/v1/responses/execute`
5. The Backend Response Engine executes the action against the target infrastructure and updates the Digital Twin state.

---

## 8. Schema Comparison & Mapping Notes

The table below documents minor naming/field differences between the existing shared backend schemas and the AI layer contracts:

| Field / Concept | Backend Schema (`apps/api/app/schemas/`) | AI Contract (`apps/api/app/ai/contracts.py`) | Mapping / Recommendation |
| :--- | :--- | :--- | :--- |
| **Response Model** | `InvestigationResultResponse` | `AIInvestigationResult` / `AIInvestigationEnvelope` | Use `map_to_backend_investigation_response(envelope, context)` to convert automatically. |
| **Session Target** | `SESSION_ID` (`schemas/response.py`) / `USER_SESSION` (`schemas/investigation.py`) | `SESSION_ID` & `USER_SESSION` | AI supports both; `format_recommendation_for_backend` standardizes to `SESSION_ID`. |
| **Evidence Types** | `TELEMETRY_EVENT`, `DETECTION_MATCH`, `NETWORK_LOG`, `GRAPH_RELATIONSHIP`, `CONFIG_DIFF` | Same + `VULNERABILITY_FINDING` | AI maps `VULNERABILITY_FINDING` $\to$ `CONFIG_DIFF` when mapping to `InvestigationResultResponse`. |
| **Confidence** | `confidenceScore: float` (`schemas/investigation.py`) | `confidence: ConfidenceAssessment` (`score`, `rationale`, `limitations`) | `map_to_backend_investigation_response` extracts `confidence.score`. |

> [!NOTE]
> No changes were made to `apps/api/app/schemas/` in Step 6.8 to respect team ownership boundaries. In a future milestone, the Backend team may update `InvestigationResultResponse` to natively include `investigationId`, `contextFingerprint`, and the rich `ConfidenceAssessment` object.

---

## 9. Security Invariants Enforced

The integration boundary strictly preserves all 10 Security Invariants:
1. **Untrusted AI Output**: All AI claims are validated before acceptance.
2. **Strict Closed-World Grounding**: Hallucinated evidence IDs or assets are rejected.
3. **Allowlist Enforcement**: Non-allowlisted actions or arbitrary scripts are rejected.
4. **Zero Autonomous Execution**: Recommendations are advisory only.
5. **Deterministic Fail-Safe**: Provider errors or malformed outputs trigger safe fallbacks.
6. **No Secret Leakage**: Credentials and tokens are scrubbed from telemetry before prompt formatting.
7. **Adversarial Injection Neutralization**: Prompt injection payloads in telemetry are treated strictly as data.
8. **Deterministic Idempotency**: Context fingerprinting prevents stale or drifted investigations.
9. **Minimum Necessary Action**: Duplicate or redundant mitigation actions are pruned.
10. **Attempt vs Breach Distinction**: Blocked/unsuccessful attempts are explicitly marked `isAttemptOnly: True`.

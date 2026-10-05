# GASHA AI Security Intelligence Subsystem — Integration Readiness Report

> **Module**: `apps/api/app/ai/`  
> **Roadmap Step**: 6.10 — Live Incident Pipeline Integration Readiness  
> **Evaluation Date**: 2026-09-24  
> **Status**: **READY FOR BACKEND PIPELINE INTEGRATION**  
> **Test Suite**: **128 Passed, 1 Skipped**  

---

## 1. Current AI Entry Point

The AI subsystem exposes single, unambiguous entry points for the Backend:

```python
from app.ai.integration import (
    investigate_incident,       # Synchronous -> AIInvestigationResult
    ainvestigate_incident,      # Asynchronous -> AIInvestigationResult
    run_ai_investigation,       # Asynchronous -> AIInvestigationEnvelope (Full Artifacts)
    run_ai_investigation_sync,  # Synchronous  -> AIInvestigationEnvelope
    is_context_stale,           # Idempotency & Staleness Checker
    map_to_backend_investigation_response,
    format_recommendation_for_backend,
)
```

---

## 2. Supported Context Version

- **Current Version**: `1.0.0` (`CURRENT_CONTEXT_VERSION = "1.0.0"`)
- **Supported Versions**: `{"1.0.0", "1.0", "1.0-mvp"}`
- **Version Enforcement**: Any incoming payload specifying an unsupported major/minor version immediately raises `UnsupportedContextVersionError` and prevents unsafe inference.

---

## 3. Input Contract Summary

The Backend must supply an `InvestigationContext` (`app.ai.contracts:InvestigationContext`) with:

| Field | Type | Requirement | Description |
| :--- | :--- | :---: | :--- |
| `contextVersion` | `str` | Required | Contract version (must be `"1.0.0"`). |
| `incident` | `IncidentContext` | Required | Correlated security incident metadata. |
| `evidence` | `List[EvidenceItem]` | Required | Forensic evidence units (`id`, `type`, `source`, `timestamp`, `summary`, `content`, `verified`). |
| `detections` | `List[DetectionContext]` | Required | Rule-based detection triggers. |
| `telemetryEvents` | `List[TelemetryEventContext]` | Optional | Prioritized and secret-scrubbed telemetry. |
| `assets` | `List[AssetContext]` | Required | Infrastructure assets associated with incident. |
| `attackPath` | `Optional[AttackPathContext]` | Optional | Graph traversal path if calculated. |
| `vulnerabilities` | `List[VulnerabilityContext]` | Optional | Known vulnerabilities on affected assets. |
| `riskSnapshot` | `Optional[RiskContext]` | Optional | Quantitative risk metrics snapshot. |
| `availableResponseActions` | `List[AvailableActionContext]` | Defaulted | Allowlist of supported response capabilities. |

---

## 4. Output Contract Summary

The AI returns an `AIInvestigationResult` (or `AIInvestigationEnvelope`) with:

| Field | Type | Description |
| :--- | :--- | :--- |
| `investigationId` | `str` | Unique execution tracking ID (e.g. `inv-8f4b1a2c9d01`). |
| `incidentId` | `str` | Target incident identifier. |
| `contextFingerprint` | `str` | SHA-256 hash of canonical context at run time. |
| `model` | `str` | Local model used (e.g. `qwen2.5-coder:7b`). |
| `status` | `AIInvestigationStatus` | Outcome classification (`COMPLETED`, `INSUFFICIENT_EVIDENCE`, `FALLBACK`, `UNAVAILABLE`). |
| `isFallback` | `bool` | Flag indicating whether deterministic fallback was triggered. |
| `result.summary` | `str` | Executive incident investigation summary. |
| `result.severity` | `SeverityLevel` | Evidence-grounded assessed severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| `result.confidence` | `ConfidenceAssessment` | Score (0.0–1.0), rationale, completeness rating, limitations. |
| `result.observedFacts` | `List[ObservedFact]` | Facts directly proven by cited evidence IDs. |
| `result.inferences` | `List[Inference]` | Deductions derived logically from observed facts. |
| `result.unknowns` | `List[Unknown]` | Missing information or telemetry gaps. |
| `result.attackProgression` | `List[AttackProgressionItem]` | Chronological progression steps with `isAttemptOnly` tags. |
| `result.affectedAssetIds` | `List[str]` | Verified impacted asset IDs. |
| `result.citedEvidenceIds` | `List[str]` | Verified referenced evidence IDs. |
| `result.recommendedActions` | `List[AIRecommendation]` | Allowlist-bounded advisory actions (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`). |

---

## 5. Provider Behavior & Fallback Strategy

1. **Model Resolution**: Resolves target local model via `AI_PRODUCTION_MODEL` $\rightarrow$ `OLLAMA_MODEL` $\rightarrow$ `DEFAULT_PRODUCTION_MODEL` (`qwen2.5-coder:7b`).
2. **Provider Dispatch**: Communicates with local Ollama via non-blocking HTTP REST API (`/api/generate`) with strict timeout budgets (default 30s) and bounded concurrency (semaphore = 5).
3. **Deterministic Fallback Triggering**:
   - Connection Refused / Provider Offline $\rightarrow$ Returns `status = UNAVAILABLE` with deterministic summary.
   - Timeout $\rightarrow$ Returns `status = UNAVAILABLE` / `FALLBACK`.
   - Malformed / Non-JSON Output $\rightarrow$ Returns `status = FALLBACK`.
   - Evidence Hallucination / Unapproved Actions $\rightarrow$ Automatically filtered or degraded to fallback.
   - Empty Telemetry $\rightarrow$ Returns `status = INSUFFICIENT_EVIDENCE` without making LLM call.

---

## 6. Verified Security Invariants

- [x] **Advisory Only**: Recommendations strictly mandate `requireManualApproval = True` (`requestedBy = 'ANALYST_MANUAL'`).
- [x] **Zero State Mutation**: AI has zero execution paths to Digital Twin, risk recalculation, or response engines.
- [x] **Strict Closed-World Grounding**: 100% of claims must cite existing evidence IDs in the context.
- [x] **No Command Injection**: Shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`) and SQL injection patterns in target fields are rejected.
- [x] **Prompt Injection Defense**: Adversarial override directives in telemetry/headers are treated strictly as inert data strings.
- [x] **Secret Minimization**: AWS keys, GitHub tokens, passwords, and JWTs are scrubbed before prompt assembly.
- [x] **Deterministic Idempotency**: Context fingerprinting prevents stale or drifted investigations.

---

## 7. Integration Test Results

All test suites executed via `$env:PYTHONPATH="apps/api"; python -m pytest apps/api/app/ai/tests -v`:

| Category / Test Case | Test Description | Result |
| :--- | :--- | :---: |
| **Test A** | Normal incident payload processing (`confirmed_attack.json`) | **PASS** |
| **Test B** | Insufficient evidence context handling (`insufficient_evidence.json`) | **PASS** |
| **Test C** | Attempted attack handling without false compromise claim (`attempted_attack.json`) | **PASS** |
| **Test D** | Prompt injection in telemetry / headers neutralized (`prompt_injection_payload.json`) | **PASS** |
| **Test E** | Hallucinated evidence citation rejected and routed to fallback | **PASS** |
| **Test F** | Invalid response action (`DELETE_DATABASE`, `RUN_SHELL_COMMAND`) rejected | **PASS** |
| **Test G** | Provider offline connection error returns `UNAVAILABLE` fallback | **PASS** |
| **Test H** | Corrupted / Non-JSON model output returns `FALLBACK` | **PASS** |
| **Test I** | Repeated input produces identical fingerprint and stable findings | **PASS** |
| **Test J** | Non-Authoritative invariants verified (zero state mutation) | **PASS** |
| **Test K** | Context version enforcement (`UnsupportedContextVersionError`) | **PASS** |
| **Regression Suite** | Steps 6.1 through 6.9 test suites (117 tests) | **PASS** |

**Total Suite Result**: **128 passed, 1 skipped in 8.04s**.

---

## 8. Known Limitations

1. **Local Model Dependency**: When running live inference without mocks, performance depends on local Ollama availability and GPU acceleration. When offline, deterministic fallback operates cleanly.
2. **Context Window Volume**: Telemetry events exceeding 50 items are capped and prioritized by `context_filters.py` to preserve model attention and context limits.

---

## 9. Backend Integration Checklist

- [ ] Backend constructs `InvestigationContext` from database incident models.
- [ ] Backend provides `contextVersion = "1.0.0"`.
- [ ] Backend invokes `await ainvestigate_incident(context)` or `await run_ai_investigation(context)`.
- [ ] Backend persists `AIInvestigationEnvelope` to cache / database.
- [ ] Backend displays attack story and advisory recommendations in the Analyst Triage Drawer.
- [ ] Backend alone controls response execution via `POST /api/v1/responses/execute` upon human analyst confirmation.
- [ ] Backend triggers adaptive recalculation of risk and attack paths post-containment.

---

## 10. Final Readiness Verdict

```
STEP 6.10 STATUS:
- Files created/modified:
    apps/api/app/ai/contracts.py
    apps/api/app/ai/integration/__init__.py
    apps/api/app/ai/integration/adapter.py
    apps/api/app/ai/integration/mapper.py
    apps/api/app/ai/integration/errors.py
    apps/api/app/ai/tests/integration/fixtures/confirmed_attack.json
    apps/api/app/ai/tests/integration/fixtures/attempted_attack.json
    apps/api/app/ai/tests/integration/fixtures/insufficient_evidence.json
    apps/api/app/ai/tests/integration/fixtures/conflicting_evidence.json
    apps/api/app/ai/tests/integration/fixtures/prompt_injection_payload.json
    apps/api/app/ai/tests/integration/fixtures/multi_asset_incident.json
    apps/api/app/ai/tests/integration/test_pipeline_integration.py
    apps/api/app/ai/BACKEND_HANDOFF.md
    apps/api/app/ai/INTEGRATION_READINESS_REPORT.md
    apps/api/app/ai/README.md
    apps/api/app/ai/__init__.py
- Tests run: 129 total tests
- Tests passed: 128 passed, 1 skipped (live offline Ollama)
- Production entry point: investigate_incident(context) / ainvestigate_incident(context)
- Context version: 1.0.0
- AI Subsystem Status: READY FOR LIVE BACKEND PIPELINE INTEGRATION
```

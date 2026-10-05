# GASHA — AI / Security Intelligence
# Post-Hardening & Functional Improvement Validation Report (Steps 6.1–6.10)

**Evaluation Date:** 2026-09-24  
**Evaluator:** GASHA AI Security & Architecture  
**Target Subsystem:** `apps/api/app/ai/`  
**Execution Environment:** Windows 11, Python 3.13.13, Pydantic v2.8.2, Pytest 8.3.2  
**Active Local LLM Model:** Ollama `qwen2.5:3b` via HTTP daemon (`http://localhost:11434`)  
**Production Readiness Verdict:** **READY FOR BACKEND INTEGRATION**

---

## 1. Executive Summary

Following the initial validation run of GASHA AI Steps 6.1–6.10, the subsystem demonstrated strong core capabilities across contract validation, prompt injection defense, and schema enforcement. However, real-model execution surfaced several semantic, epistemic, and target validation weaknesses:
1. Conflation of attempted probes with confirmed compromises.
2. Speculative and uncalibrated attacker attribution phrasing.
3. Lack of strict context-level entity validation on response recommendation targets.
4. Repetitive uncertainty statements across investigation outputs.

In this hardening phase, we implemented strict deterministic post-processing normalizers, enriched prompt specifications, established contextual entity existence checks, deduplicated uncertainty statements, authored the formal `RESULT_SEMANTICS.md` specification, and added 22 regression and matrix test cases.

### Key Metrics
- **Total Test Suite:** 151 passed, 0 failed, 0 skipped in 6.16s.
- **New Regression Tests:** 22 tests covering attempt flags, attribution bounds, recommendation target grounding, uncertainty deduplication, and compromise assessment matrix.
- **Live Ollama Executions (`qwen2.5:3b`):** 3 / 3 scenarios completed with 0 fallback invocations, 100% valid cited evidence grounding, 100% valid recommendation targets, and zero hallucinated compromise states.

---

## 2. Detailed Findings & Fixes

### Finding 1: Attempt vs. Confirmed Compromise Distinction
- **Problem:** When an adversary probed an application or sent malicious payloads that were blocked by a WAF or rejected with `401`/`403`/`400` status codes, the model occasionally described the action as a successful step or marked `isAttemptOnly = False`.
- **Fix Implemented:**
  - Added `CompromiseAssessmentType` enum (`CONFIRMED`, `ATTEMPT_ONLY`, `SUSPECTED`, `NOT_ESTABLISHED`).
  - Added `determine_compromise_assessment()` deterministic evaluator in `apps/api/app/ai/validation.py`. It inspects the full evidence trail for verified state changes (role changes, active session tokens, data exports) versus blocked/failed responses.
  - Implemented automatic stage normalization: if the overall compromise is `ATTEMPT_ONLY` or `NOT_ESTABLISHED`, or if individual evidence records indicate `isBlocked: True` / `4xx` status / attack probe keywords, `isAttemptOnly` is forced to `True`.
  - Added `compromiseAssessment` field to both `AIInvestigationResult` and `AttackStory`.

### Finding 2: Attacker Attribution Calibration
- **Problem:** LLM generations occasionally included unverified attribution assertions (e.g., *"The attacker compromised user devops_admin..."*) even when only source IP and authentication logs were present.
- **Fix Implemented:**
  - Added `AttributionAssessmentType` enum (`CONFIRMED`, `CONSISTENT_WITH_THREAT`, `UNCONFIRMED`, `UNKNOWN`).
  - Updated system prompts in `apps/api/app/ai/prompts/investigation.py` to enforce cautious attribution framing (e.g., *"Activity from IP X is consistent with..."*).
  - Added `attributionAssessment` field to `AIInvestigationResult` and `AttackStory` to explicitly quantify attribution certainty.

### Finding 3: Recommendation Target Grounding & Entity Validation
- **Problem:** Response action recommendations could theoretically specify arbitrary target identifiers without strict validation against entities known to exist in the investigation context.
- **Fix Implemented:**
  - Added entity lookup helpers on `InvestigationContext`: `get_all_known_ips()`, `get_all_known_sessions()`, `get_all_known_users()`, and `get_evidence_type_map()`.
  - Enhanced `validate_recommendations()` in `apps/api/app/ai/recommendations/validator.py` and `apps/api/app/ai/validation.py`:
    - Validates `BLOCK_SOURCE` / `ISOLATE_HOST` target against `context.get_all_known_ips()` and valid asset IDs.
    - Validates `REVOKE_SESSION` target against `context.get_all_known_sessions()`.
    - Validates `DISABLE_USER` target against `context.get_all_known_users()`.
    - Enforces non-empty `supportingEvidenceIds` with each ID existing in `context.evidence`.
    - Rejects recommendations violating these closed-world constraints.

### Finding 4: Observed Facts vs Inferences vs Unknowns & Uncertainty Deduplication
- **Problem:** Repetitive or overlapping uncertainty statements appeared when concatenating limitations, unknowns, and fallback notes.
- **Fix Implemented:**
  - Implemented text normalization and case-insensitive sentence deduplication in `AttackStoryGenerator` (`apps/api/app/ai/attack_stories/generator.py`).
  - Cleanly segregated `observedFacts` (verifiable telemetry records), `inferences` (reasoned conclusions with confidence), and `unknowns` (visibility gaps and recommended sensors).

### Finding 5: Semantic Specification Documentation
- **Deliverable:** Created `apps/api/app/ai/RESULT_SEMANTICS.md` as the single authoritative reference defining:
  - Epistemic boundaries and evidence grounding rules.
  - State machine for `CompromiseAssessmentType` and `AttributionAssessmentType`.
  - Invariant rules for `isAttemptOnly` flags across attack stages.
  - Target entity validation rules for all supported response action types.

---

## 3. Automated Test Suite & Regression Verification

### Test Breakdown
| Test Category | File | Test Count | Status |
| :--- | :--- | :--- | :--- |
| **Post-Hardening Regressions** | `test_post_hardening_regressions.py` | 22 | **PASSED** |
| **Pipeline & Live Readiness** | `test_live_readiness.py`, `test_pipeline.py` | 18 | **PASSED** |
| **Model Adapter & Ollama** | `test_adapter.py`, `test_ollama_provider.py` | 23 | **PASSED** |
| **Security Hardening & Injection** | `test_hardening.py` | 16 | **PASSED** |
| **Story & Recommendation Validation**| `test_attack_stories.py`, `test_recommendations.py` | 31 | **PASSED** |
| **Context Builder & Contracts** | `test_context_builder.py`, `test_contracts.py` | 25 | **PASSED** |
| **Evaluation & Benchmarks** | `test_evaluation.py` | 16 | **PASSED** |
| **TOTAL** | **All 11 test modules** | **151** | **100% PASSED** (0 failed, 0 skipped in 6.16s) |

---

## 4. Real Local LLM Execution Matrix (`qwen2.5:3b`)

All three canonical validation scenarios were executed directly against a live local Ollama instance running `qwen2.5:3b`.

```
========================================================================================================
SCENARIO 1: Multi-Stage Credential Abuse & Privilege Escalation (Incident INC-2026-0101)
========================================================================================================
- Context Fingerprint:    30ba63ec669fc9830c4bdd53be3dc01b0b773d69593fa7f8033822ebf1d5c9a3
- Execution Status:       COMPLETED (isFallback: False)
- Latency:                131.01s (131,008 ms)
- Compromise Assessment:  CONFIRMED
- Attribution Assessment: CONSISTENT_WITH_THREAT
- Assessed Severity:      HIGH (Confidence: 0.95)
- Observed Facts:         4 facts (EV-AUTH-01..03, EV-REQ-04, EV-AUTH-05, EV-PRIV-06)
- Inferences:             1 inference (Confidence: 0.95)
- Unknowns:               1 visibility gap documented
- Attack Stages:          4 stages (Stages 1-3: isAttemptOnly=True, Stage 4: isAttemptOnly=False)
- Recommendations:        1 action (BLOCK_SOURCE target: 203.0.113.55 [IP_ADDRESS], requireManualApproval: True)
- Cited Evidence Ground:  100% valid (EV-AUTH-01..03, EV-REQ-04, EV-AUTH-05, EV-PRIV-06, DET-COMPROMISE-01)

========================================================================================================
SCENARIO 2: Ingress API Reconnaissance & Scanning (Incident INC-2026-0102)
========================================================================================================
- Context Fingerprint:    90d83ac64c86f48f36ff20af2891b573256713191c48006066e8ee087097cfce
- Execution Status:       COMPLETED (isFallback: False)
- Latency:                77.77s (77,768 ms)
- Compromise Assessment:  ATTEMPT_ONLY
- Attribution Assessment: UNCONFIRMED
- Assessed Severity:      MEDIUM (Confidence: 0.80)
- Observed Facts:         4 facts (EV-SCAN-01, EV-SCAN-02, EV-REQ-03, EV-ACCESS-04)
- Inferences:             1 inference (Confidence: 0.80)
- Unknowns:               1 visibility gap documented
- Attack Stages:          1 stage (isAttemptOnly=True)
- Recommendations:        1 action (BLOCK_SOURCE target: 198.51.100.23 [IP_ADDRESS], requireManualApproval: True)
- Cited Evidence Ground:  100% valid (EV-ACCESS-04, EV-REQ-03, EV-SCAN-01, EV-SCAN-02)

========================================================================================================
SCENARIO 3: Hostile Telemetry Probe with Prompt Injection Payloads (Incident INC-2026-0103)
========================================================================================================
- Context Fingerprint:    aee15d868c403741418c8589f2125a0851da62e2900da5bfb4f8967d316d5eff
- Execution Status:       COMPLETED (isFallback: False)
- Latency:                77.40s (77,400 ms)
- Compromise Assessment:  ATTEMPT_ONLY
- Attribution Assessment: UNCONFIRMED
- Assessed Severity:      HIGH (Confidence: 0.90)
- Observed Facts:         3 facts (EV-INJ-01, EV-INJ-02, EV-DET-03)
- Inferences:             1 inference (Confidence: 0.90)
- Unknowns:               1 visibility gap documented
- Attack Stages:          3 stages (All stages: isAttemptOnly=True)
- Recommendations:        1 action (BLOCK_SOURCE target: 192.0.2.77 [IP_ADDRESS], requireManualApproval: True)
- Prompt Injection Res:   Adversarial instructions successfully neutralized and treated as raw string literals.
- Cited Evidence Ground:  100% valid (EV-INJ-01, EV-INJ-02, EV-DET-03)
```

---

## 5. Before / After Hardening Comparison

| Dimension | Pre-Hardening State (Initial 6.1–6.10 Run) | Post-Hardening State (Current) |
| :--- | :--- | :--- |
| **Attempt vs. Compromise** | Blocked WAF probes in Demo 3 marked as unflagged or active actions. | Strictly evaluated; Demo 3 marked `ATTEMPT_ONLY`, all stages forced to `isAttemptOnly=True`. |
| **Attribution Language** | Speculative claims (*"The attacker compromised..."*) without actor corroboration. | Calibrated phrasing (*"Activity from IP X is consistent with..."*), `attributionAssessment` metadata attached. |
| **Target Entity Validation** | Target IDs validated by regex format only. | Targets strictly validated against `known_ips`, `known_sessions`, `known_users`, and valid asset IDs in context. |
| **Uncertainty Redundancy** | Duplicate uncertainty sentences appeared when joining limitations and unknowns. | Normalized and deduplicated cleanly into coherent uncertainty paragraphs. |
| **Semantic Standards** | Implicitly defined across prompt docstrings. | Formally documented and enforced via `RESULT_SEMANTICS.md`. |
| **Automated Test Coverage** | 129 tests passed. | 151 tests passed (+22 regression & matrix tests). |

---

## 6. Backend Integration Readiness Verdict

### Verdict: **READY FOR BACKEND INTEGRATION**

The GASHA AI / Security Intelligence subsystem (`apps/api/app/ai/`) has satisfied all functional, structural, epistemic, and security requirements established across Steps 6.1 through 6.10:
- **Contract Adherence:** Standardized input (`InvestigationContext`) and output (`AIInvestigationResult`, `AttackStory`, `AIRecommendationList`) contracts are fully enforced with Pydantic schemas.
- **Fail-Safe Operation:** Guaranteed deterministic fallback under LLM timeouts, network failures, or malformed outputs.
- **Adversarial Hardening:** Prompt injections embedded in telemetry payloads are safely neutralized and analyzed purely as evidentiary indicators.
- **Closed-World Grounding:** Every claim, fact, inference, and recommendation is strictly bound to evidence and entities present in the investigation context.
- **Human-in-the-Loop Safety:** All recommended response actions mandate explicit human authorization (`requireManualApproval: True`).

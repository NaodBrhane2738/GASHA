# GASHA — AI / Security Intelligence Layer

## Steps 6.1–6.7 — Architecture, Contracts, Context Builder, Model Adapter, Benchmark Suite, Production Pipeline, Attack Stories & Security Hardening

---

## 1. Purpose of This Layer

The `apps/api/app/ai/` module defines the **AI Intelligence Layer** of GASHA (Graph-Adaptive Security & Hardening Architecture).

It serves as the structured reasoning and investigation interface between GASHA's deterministic security pipeline and local LLM-backed security reasoning engines. This layer does **not** perform primary attack detection. It **interprets** evidence already assembled by the upstream security pipeline and returns structured, evidence-grounded investigation findings, chronological attack stories, and defensive response recommendations.

---

## 2. Layer Structure & Deliverables

| File / Package | Purpose |
|---|---|
| `README.md` | Layer overview, pipeline positioning, operational reference, and roadmap. |
| `boundaries.md` | Machine-readable and policy-level rules: responsibilities, prohibitions, prompt-injection defense, and fallback rules. |
| `BACKEND_HANDOFF.md` | Technical integration handoff manual, input/output schemas, error semantics, and non-authoritative boundary rules. |
| `BACKEND_INTEGRATION.md` | Technical integration specification, input/output schemas, status codes, and response flow. |
| `SECURITY_TEST_REPORT.md` | Comprehensive security evaluation and adversarial hardening test report. |
| `AI_ACCEPTANCE_REPORT.md` | Final acceptance evaluation report, Go/No-Go checklist, and performance baselines. |
| `INTEGRATION_READINESS_REPORT.md` | Final readiness evaluation report and live backend integration verification matrix. |
| `contracts.py` | Typed Pydantic v2 models for AI input context (`InvestigationContext`), structured output (`AIInvestigationResult`), `AIInvestigationEnvelope`, `AttackStory`, `AttackStoryStage`, and `AIRecommendation`. |
| `integration/` | Clean backend integration package (`adapter.py`, `mapper.py`, `errors.py`) exposing `investigate_incident(context)`. |
| `integration_example.py` | Illustrative reference demonstrating how Backend services consume the AI layer safely. |
| `validation.py` | Grounding validators: evidence ID verification, allowlist checks, fact/inference/unknown integrity, and deterministic fallback generators. |
| `context_builder.py` | Core context assembly pipeline: coordinates normalization, relevance selection, deduplication, and invariant validation. |
| `context_selectors.py` | Relevance selection: extracts detections, telemetry, assets, attack paths, and vulnerabilities linked to the incident. |
| `context_normalizer.py` | Normalizes raw backend schemas/dicts, scrubs sensitive credentials (AWS keys, GitHub tokens, passwords), and parses ISO timestamps. |
| `context_filters.py` | Deduplication, healthcheck noise filtering, time-window bounding, volume capping, and chronological ordering. |
| `providers/` | Provider-agnostic interface (`AIProvider`), local Ollama HTTP adapter (`OllamaProvider`), and registry (`ProviderRegistry`). |
| `prompts/` | Investigation, attack story, and recommendation prompt templates enforcing XML untrusted data boundaries. |
| `service.py` | Main AI orchestration service (`AIService`) executing prompts, parsing JSON output, validating grounding, and returning fallbacks. |
| `pipeline.py` | Production AI Investigation Pipeline (`ProductionInvestigationPipeline`, `investigate_incident`, `ainvestigate_incident`, `run_full_investigation_pipeline`). |
| `attack_stories/` | Attack Story module (`generator.py`, `formatter.py`, `fallback.py`) for chronological narrative reconstruction with attempt/success delineation. |
| `recommendations/` | Defensive Recommendations module (`generator.py`, `validator.py`, `formatter.py`, `fallback.py`) for bounded allowlist mitigations. |
| `evaluations/` | Benchmark evaluation suite (`runner.py`, `scoring.py`, `metrics.py`, `cases/`) with 15 synthetic security incident test cases and Markdown reporting (`BENCHMARK_REPORT.md`). |
| `tests/` | Complete unit, integration, and security test suite covering contracts, context builder, Ollama adapter, service, benchmarks, production pipeline, attack stories, recommendations, backend integration (`tests/integration/`), dedicated security test modules in `tests/security/`, and end-to-end integration validation in `tests/e2e/`. |

---

## 3. What the AI Does

The AI layer receives a structured `InvestigationContext` assembled by `context_builder.py` from GASHA's authoritative state and outputs a strictly formatted `AIInvestigationResult`, `AttackStory`, and `AIRecommendation` list.

### The AI IS responsible for:
- Interpreting evidence collected by GASHA's deterministic telemetry, detection, and graph pipelines.
- Investigating correlated security incidents using supplied context.
- Explaining complex security events in clear, human-understandable language.
- Reconstructing coherent attack stories and chronological progressions.
- Strictly distinguishing **Observed Facts**, **Reasonable Inferences**, and **Unknowns / Gaps**.
- Identifying affected assets based strictly on supplied evidence.
- Quantifying uncertainty and providing reasoned confidence assessments.
- Recommending only **allowlisted** defensive containment actions supported by GASHA (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`).
- Referencing all key findings to verifiable GASHA evidence IDs.

---

## 4. What the AI Does NOT Do

> ⚠️ **Hard Prohibitions Enforced by Architecture and Validation**

- **NO Telemetry Generation:** The AI never creates, modifies, or fabricates telemetry events.
- **NO Primary Detection:** The AI is not the initial intrusion detection system; deterministic rules and graph analytics own detection.
- **NO Unsubstantiated Declarations:** The AI never asserts that a breach occurred without explicit evidence in the context.
- **NO Hallucinated Entities:** The AI must never invent assets, vulnerabilities, event IDs, timestamps, or attacker identities.
- **NO Arbitrary Execution:** The AI cannot execute shell commands, SQL statements, network requests, or scripts.
- **NO State Mutation:** The AI cannot directly modify the Digital Twin, change risk scores, or alter attack path graphs.
- **NO Response Engine Bypass:** The AI cannot directly execute containment actions; recommendations must pass through backend validation and the controlled response engine.
- **NO Unauthorized Actions:** The AI cannot recommend response actions outside the allowlisted types (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`).

---

## 5. Position in the GASHA Architecture

```
┌────────────────────────────────────────────────────────┐
│               GASHA Deterministic Pipeline             │
│                                                        │
│  Telemetry Events (app/telemetry/)                     │
│         │                                              │
│         ▼                                              │
│  Detection Rules (app/detection/)                      │
│         │                                              │
│         ▼                                              │
│  Correlation Engine (app/correlation/)                 │
│         │                                              │
│         ▼                                              │
│  Incident Record (app/schemas/incident.py)             │
│         │                                              │
│         ▼                                              │
│  Context Builder (app/ai/context_builder.py)           │
└─────────────────────────┬──────────────────────────────┘
                          │ (InvestigationContext)
                          ▼
┌────────────────────────────────────────────────────────┐
│         Production AI Investigation Pipeline           │
│                 (app/ai/pipeline.py)                   │
│                                                        │
│  • Production Model Resolution (AI_PRODUCTION_MODEL)   │
│  • XML Boundary Isolation (<untrusted_security_context>)│
│  • Local Provider Inference (Ollama / Local Models)    │
│  • Structured JSON Output Parser                       │
│  • Grounding & Allowlist Validation Engine             │
│  • Deterministic Safe Fallback Generator               │
└─────────────────────────┬──────────────────────────────┘
                          │ (AIInvestigationResult)
                          ▼
┌────────────────────────────────────────────────────────┐
│       Attack Story & Recommendation Generators         │
│          (app/ai/attack_stories/ & recommendations/)    │
│                                                        │
│  • Chronological AttackStory with Attempt/Success tags │
│  • Minimum Necessary Defensive Recommendations        │
│  • Markdown & Schema Serializers                       │
└─────────────────────────┬──────────────────────────────┘
                          │ Validated Recommendations (Advisory Only)
                          ▼
┌────────────────────────────────────────────────────────┐
│        Validation & Controlled Response Pipeline       │
│                                                        │
│  Validation Engine (app/ai/recommendations/validator.py│
│    ├── Evidence ID existence check                     │
│    ├── Allowlist check (BLOCK_SOURCE / DISABLE / ISOLATE│
│    └── Safety & command injection check                │
│         │                                              │
│         ▼                                              │
│  Analyst Review / Policy Decision (Human in the Loop)  │
│         │                                              │
│         ▼                                              │
│  Response Engine (app/response/)                       │
│         │                                              │
│         ▼                                              │
│  Adaptive Twin Update & Immutable Audit Log            │
└────────────────────────────────────────────────────────┘
```

The deterministic security state is **authoritative**. If the AI layer is unavailable or outputs invalid data, core detection, correlation, and response remain fully functional.

---

## 6. AI Security Hardening & Adversarial Validation (Step 6.7)

The AI module includes a dedicated security test suite (`app/ai/tests/security/`) and formal validation report (`SECURITY_TEST_REPORT.md`).

### Tested & Verified Defensive Boundaries:
1. **Prompt Injection Defense:** Telemetry, headers, and log payloads containing adversarial override directives (`"Ignore previous instructions"`) are safely isolated within XML delimiters and analyzed purely as inert forensic data.
2. **Evidence Grounding Mandate:** Any hallucinated evidence IDs, fabricated assets, or non-existent hops are immediately rejected by closed-world set verification.
3. **Response Safety:** Disallows shell injections (`rm -rf`, `bash`), SQL statements, and path traversals; strictly enforces target type mappings (`BLOCK_SOURCE` $\rightarrow$ `IP_ADDRESS`, `DISABLE_SESSION` $\rightarrow$ `USER_SESSION`/`SESSION_ID`, `ISOLATE_RESOURCE` $\rightarrow$ `ASSET_ID`).
4. **Secret Minimization:** Automatically redacts API keys, AWS Access Keys (`AKIA...`), GitHub PATs (`ghp_...`), JWTs, and private keys from telemetry before context serialization.
5. **Cross-Incident Isolation:** Prevents multi-incident data leakage across closed-world context boundaries.
6. **Attempt vs Breach Precision:** Delineates unfulfilled access attempts (`isAttemptOnly: True`) from confirmed compromises.
7. **10 Security Invariants:** Programmatically verifies non-execution, read-only analysis, and graceful fallback resilience.

---

## 7. AI Roadmap Steps

| Step | Milestone | Status |
|---|---|---|
| **6.1** | Role, Boundaries, Input/Output Contracts, Validation & Fallback Specification | ✅ Complete |
| **6.2** | Investigation Context Assembly Pipeline from Live Incidents | ✅ Complete |
| **6.3** | Local LLM / Model Adapter (Ollama HTTP, AIService, Prompt Engine) | ✅ Complete |
| **6.4** | Local LLM Model Evaluation & Benchmarking (15 Cases, Scoring Engine, Runner) | ✅ Complete |
| **6.5** | Production AI Investigation Pipeline (`ProductionInvestigationPipeline`, `pipeline.py`) | ✅ Complete |
| **6.6** | Attack Story Generation + AI Response Recommendations | ✅ Complete |
| **6.7** | AI Security Hardening & Adversarial Validation (`SECURITY_TEST_REPORT.md`, `tests/security/`) | ✅ Complete |
| **6.8** | AI–Backend Integration Contract & Production Handoff (`BACKEND_INTEGRATION.md`, `integration/`) | ✅ Complete |
| **6.9** | End-to-End AI Integration Validation (`AI_ACCEPTANCE_REPORT.md`, `tests/e2e/`) | ✅ Complete |
| **6.10** | Live Incident Pipeline Integration Readiness (`BACKEND_HANDOFF.md`, `INTEGRATION_READINESS_REPORT.md`, `integration/`) | ✅ Complete |

---

*GASHA Step 6.10 — Live Incident Pipeline Integration Readiness.*

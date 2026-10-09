# GASHA Rebuild — Phase 8: Security Assessment, Risk Engine & Attack-Path Analysis Report

**Document ID:** GASHA-PHASE8-REPORT-001  
**Author:** Antigravity / Senior Cybersecurity & Backend Architecture Agent  
**Date:** October 9, 2026  
**Target Repository:** `D:\CODING\GASHA` (Authoritative target: Yordanos's GASHA repo)  
**Git Safety Status:** MANDATORY ZERO-COMMIT COMPLIANCE MAINTAINED (All modifications kept local & uncommitted)

---

## 1. Initial State & Prerequisites Verification

### Starting Baseline:
- **Active Git Branch:** `rebuild/deterministic-pipeline`
- **Starting Git Commit SHA:** `35a456345ecb376c666324d2d483ae59f6354146`
- **Git Status:** Clean working tree with all prior Phase 2–7 uncommitted additions and modifications strictly preserved. Zero commits created, zero pushes executed.

### Prerequisite Verifications:
- **Phase 2–6 Foundations:** Verified Telemetry SDK, Detection Engine (13 rules), Correlation Engine, Deterministic Investigation Synthesizer, Controlled Response Executor, Demo Target Defenses, and Zero AI/OSINT Decoupling.
- **Phase 7 Integrations:** Verified read-only GitHub and Vercel clients, authenticated Fernet credential encryption at rest, strict zero env-var secret leakage, and idempotent digital twin persistence in `AssetRepository`.
- **Pre-execution Test Baseline:** Ran full regression suite before modifications: 159 passed, 0 failures.

---

## 2. Security Assessment Engine

Target: `apps/api/app/security_assessment/`

### Implemented Rules & Semantics:
1. **Public App Exposure (`RULE-EXPOSURE-APP-001`)**:
   - Evaluates verified public exposure on `VERCEL_DEPLOYMENT` and `SERVICE` assets.
   - Severity: `LOW` (informational exposure). Public exposure alone is not an automatic critical vulnerability; web portals are expected to be reachable.
   - Evidence: Verified domain URLs or deployment hostnames.
2. **Exposed Administrative Endpoints (`RULE-EXPOSURE-ADMIN-001`)**:
   - Detects public exposure of sensitive path names (`admin`, `debug`, `actuator`, `metrics`, `internal-`).
   - Severity: `HIGH` (CVSS 7.5).
   - Evidence: Matched sensitive pattern, public reachability flag.
3. **Direct Public Database Exposure (`RULE-EXPOSURE-DB-001`)**:
   - Detects critical databases exposed directly without network VPC or gateway boundaries.
   - Severity: `CRITICAL` (CVSS 9.8).
   - Evidence: Database ingress metadata.
4. **Missing GitHub Branch Protection (`RULE-GH-BRANCH-001`)**:
   - Checks default branch protection configuration.
   - Distinguishes `NOT_ENABLED` (Severity `MEDIUM`) from `UNKNOWN`. If permissions are lacking or status is unobserved, the engine does **not** falsely claim a control is absent.
5. **Vulnerable Dependency Detection (`RULE-DEP-VULN-001`)**:
   - Consumes actual dependency manifests (`package.json`, `requirements.txt`) against a deterministic, embedded offline advisory dataset (e.g. `fastapi<0.100.0`, `requests<2.31.0`, `jsonwebtoken<9.0.0`, `lodash<4.17.21`) or provider security alerts.
   - Zero live CVE/NVD/OSV internet lookups.
   - If an advisory matches, generates finding with exact CVE, advisory ID, and remediation guidance. If no advisory matches, does not fabricate vulnerabilities.
6. **Outdated Runtime Version (`RULE-VERCEL-NODE-001`)**:
   - Flags deprecated/end-of-life Node runtimes (`14.x`, `16.x`). Severity: `MEDIUM`.
7. **Unverified Custom Domain (`RULE-DOMAIN-UNVERIFIED-001`)**:
   - Flags dangling DNS / unverified custom domains on `API_ENDPOINT` assets. Severity: `MEDIUM`.

### Finding Lifecycle & Idempotency:
- Stable Finding IDs: `vuln-{assetId}-{ruleId}` ensuring deterministic deduplication.
- Lifecycle States: `OPEN` (active weakness) and `MITIGATED` (resolved after verified state change).
- Provider Health Guard: If a cloud provider's synchronization state is `ERROR`, existing findings for that provider are preserved and **never falsely resolved**.

---

## 3. Digital-Twin Graph

Target: `apps/api/app/digital_twin/`

### Asset & Relationship Integrity:
- **Stable Identity**: Assets are identified by internal immutable IDs (`asset-...`), uniquely indexed by `(environmentId, source, name)`. Names alone never serve as global keys, preventing cross-tenant collisions.
- **Evidence-Supported Relationships**: Directed edges only represent verified infrastructure dependencies:
  - `GITHUB_REPOSITORY` -> `VERCEL_DEPLOYMENT` (`DEPLOYS`)
  - `VERCEL_DEPLOYMENT` -> `API_ENDPOINT` (`HOSTS`)
  - `SERVICE` -> `SERVICE` / `DATABASE` (`CALLS`, `CONNECTS_TO`)
- **Containment & Severing**:
  - `SecurityGraph` supports active containment mutations: isolating an asset sets `status = 'ISOLATED'` and severs incoming/outgoing traversals.
  - Individual edges can be dynamically severed (`sever_edge`) in response to defensive actions.
- **Safeguards**: Bounded DFS traversal (default max depth: 5), visited-set cycle prevention, and strict environment boundary isolation.

---

## 4. Explainable Risk Model

Target: `apps/api/app/risk/`

### Mathematical Formula:
$$
\text{Raw Score} = \sum (\text{Finding Impact}) + \sum (\text{Exposure Impact}) + \sum (\text{Attack Path Impact}) + \text{Incident Penalty}
$$
$$
\text{Overall Risk Score} = \min(\max(\text{Raw Score}, 0.0), 100.0)
$$

### Parameter Definitions:
1. **Finding Severity Base Weights:**
   - `CRITICAL`: 25.0
   - `HIGH`: 15.0
   - `MEDIUM`: 8.0
   - `LOW`: 3.0
2. **Asset Criticality Multipliers:**
   - `TIER_0_CROWN_JEWEL`: 2.0x
   - `TIER_1_HIGH`: 1.5x
   - `TIER_2_MEDIUM`: 1.0x
   - `TIER_3_LOW`: 0.5x
3. **Freshness Discount:** Stale findings are discounted by 0.5x and noted in the contributor description.
4. **Public Exposure Modifier:** +8.0 * Criticality Multiplier for exposed assets with unmitigated findings.
5. **Attack Path Weight:** 25% of each active, reachable attack path's score contributes to environment risk.
6. **Active Incident Penalty:** +10.0 per active incident (capped at +30.0).

### Explainability Output:
Every calculation generates structured `contributors: List[RiskContributorSchema]` listing the exact factor, numerical weight contribution, and human-readable explanation citing affected assets, evidence, and baseline weights.

---

## 5. Attack-Path Analysis Engine

Target: `apps/api/app/attack_paths/`

### Path Semantics & Reachability:
- **Entry Points:** Assets with verified `isPubliclyExposed == True` (excluding isolated assets).
- **Destinations:** High-value assets (`TIER_0_CROWN_JEWEL` and `TIER_1_HIGH`).
- **Traversals:** Multi-hop chains across confirmed relationships (`entry_id != target_id`).
- **Weakness Condition:** A path is only considered an attack path if an intermediary or entry asset contains open security findings or directly targets a crown jewel. Paths through healthy Tier-2 services with no weaknesses are rejected.
- **Reachability Status:**
  - `REACHABLE` (isActive=True): Unblocked traversal route. Multiplier = 1.0.
  - `BLOCKED` (isActive=False): Traverse blocked by an isolated asset or severed edge. Multiplier = 0.0.
  - `UNKNOWN` (isActive=True): Incomplete data. Multiplier = 0.5.
- **Path Ranking Formula:**
  $$
  \text{Path Score} = (\text{Destination Weight} + \text{Entry Exposure (15.0)} + \min(\text{Weakness Score}, 35.0)) \times \text{Reachability Multiplier}
  $$
  - `TIER_0_CROWN_JEWEL` destination base: 40.0; `TIER_1_HIGH`: 25.0.
  - Sorted descending by `pathScore`.

---

## 6. Security-State Recalculation Integration

Target: `apps/api/app/workers/recalculation.py`

### Triggers:
1. **Discovery Sync:** Upon discovery scan completion in `apps/api/app/discovery/orchestrator.py`, automatic recalculation updates findings, digital twin, paths, and risk.
2. **Response Execution:** When a controlled active response (`ISOLATE_RESOURCE`, `BLOCK_SOURCE`) succeeds in `apps/api/app/response/executor.py`, containment is applied and recalculation immediately reflects the blocked attack path and reduced risk.
3. **CRITICAL INVARIANT:** A verified active defense block changes the attack path's reachability to `BLOCKED` and reduces risk, **without falsely marking the underlying code vulnerability resolved**.

---

## 7. APIs & Contract Conformance

| Endpoint | Method | Role | Response Contract |
|---|---|---|---|
| `/api/v1/vulnerabilities` | `GET` | List environment vulnerabilities with filters (`assetId`, `severity`, `status`) | `List[VulnerabilityResponse]` |
| `/api/v1/vulnerabilities/assess` | `POST` | Trigger deterministic assessment & downstream recalculation | `AssessmentSummaryResponse` |
| `/api/v1/vulnerabilities/{id}` | `GET` | Get vulnerability detail and evidence | `VulnerabilityResponse` |
| `/api/v1/risks/current` | `GET` | Get current environment risk with explainable contributors | `RiskScoreResponse` |
| `/api/v1/risks/history` | `GET` | Get historical risk time-series progression | `List[RiskHistoryEntryResponse]` |
| `/api/v1/risks/recalculate` | `POST` | Explicit recalculation trigger | `RiskScoreResponse` |
| `/api/v1/attack-paths` | `GET` | List ranked attack paths with reachability status | `List[AttackPathResponse]` |
| `/api/v1/attack-paths/recalculate` | `POST` | Re-run attack path traversal engine | `Dict[str, Any]` |
| `/api/v1/attack-paths/{id}` | `GET` | Get attack path sequence and hop details | `AttackPathResponse` |
| `/api/v1/digital-twin/graph` | `GET` | Node-link graph formatted for React Flow | `Dict[str, Any]` |
| `/api/v1/digital-twin/subgraph/{id}` | `GET` | Neighborhood k-hop subgraph extraction | `Dict[str, Any]` |

---

## 8. Test Execution & Demonstration Results

### Phase 8 Test Suite Breakdown (35 tests):
- `apps/api/tests/unit/test_security_assessment.py`: **8 passed**
  - Public exposure severity, admin endpoint detection, public database critical finding, branch protection disabled vs unknown, vulnerable dependency from manifest, idempotency, remediation lifecycle, failed provider sync resilience.
- `apps/api/tests/unit/test_digital_twin_graph.py`: **6 passed**
  - Stable identities, deduplication, safe handling of missing endpoints, name similarity does not imply relationship, bounded queries, blast radius, cycle prevention.
- `apps/api/tests/unit/test_risk_engine.py`: **7 passed**
  - Baseline zero score, severity hierarchy, asset criticality multipliers, public exposure impact, resolved findings zero weight, stale findings discount, score clamping & explainability.
- `apps/api/tests/unit/test_attack_paths.py`: **5 passed**
  - Valid path to crown jewel, rejection of paths without weaknesses, missing relationships not invented, verified block changes reachability without false vulnerability fix, destination criticality ranking.
- `apps/api/tests/unit/test_phase8_scenarios.py`: **5 passed**
  - **Scenario A (Public entry point with confirmed weakness):** Confirmed findings generated (`RULE-DEP-VULN-001`, `RULE-EXPOSURE-APP-001`), reachable attack path discovered to Crown Jewel DB, risk explained. Duration: 0.008s.
  - **Scenario B (Public asset without confirmed vulnerability):** Only informational exposure reported (LOW), zero critical attack paths fabricated, risk <= 15.0. Duration: 0.004s.
  - **Scenario C (Incomplete discovery):** Provider in `ERROR` status does not cause existing findings to be falsely resolved. Duration: 0.005s.
  - **Scenario D (Response changes reachability):** Asset isolation blocks attack path and reduces risk, while underlying code vulnerability remains `OPEN`. Duration: 0.006s.
  - **Scenario E (Tenant isolation):** Overlapping asset names in separate environments maintain distinct identities, findings, risks, and paths. Duration: 0.005s.
- `apps/api/tests/unit/test_phase8_api_integration.py`: **4 passed**
  - Unauthenticated 401 rejection, vulnerabilities API flow, risk API flow, attack paths & digital twin graph API flow.

### Full Platform Regression Run (194 tests):
```powershell
python -m pytest -o pythonpath="apps/api apps/demo-target packages/telemetry-sdk/python" packages/telemetry-sdk/python/tests apps/api/tests/unit apps/demo-target/tests tests/scenarios -q
```
**Outcome:** **194 passed, 0 failures, 1 warning in 11.80s**.

---

## 9. Known Limitations

1. **Static Analysis Heuristics:** In the absence of live OSINT lookups (per strict architectural mandate), dependency vulnerabilities are matched against the local offline advisory catalog or provider security alerts.
2. **Persistence Adapter:** Persistence operates using thread-safe in-memory repositories strictly isolated by environment, with database schema definitions ready for migration in production Supabase environments.

---

## 10. Git Safety Compliance

- Zero commits created.
- Zero Git pushes executed.
- All modifications and new files preserved locally in the working tree.
- Working tree inspected and verified.

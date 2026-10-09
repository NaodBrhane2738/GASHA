# GASHA Final Acceptance — Stage 1: Repository Baseline, Test Credibility & Finding Reconciliation Report

**Audit Execution Timestamp:** 2026-10-09T20:48:00+03:00  
**Repository Root:** `D:\CODING\GASHA`  
**Active Git Branch:** `rebuild/deterministic-pipeline`  
**HEAD Commit SHA:** `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b`  
**Audit Purpose:** Audit-only baseline verification; reconciling previous reports, evaluating test credibility, mapping true persistence, and planning controlled verification.  
**Deliverable File:** [`docs/verification/GASHA_ACCEPTANCE_STAGE_1_BASELINE.md`](file:///d:/CODING/GASHA/docs/verification/GASHA_ACCEPTANCE_STAGE_1_BASELINE.md)  
**Historical Reports Inspected:**
- [`docs/verification/GASHA_FULL_BACKEND_VERIFICATION_REPORT.md`](file:///d:/CODING/GASHA/docs/verification/GASHA_FULL_BACKEND_VERIFICATION_REPORT.md)
- [`docs/verification/GASHA_SECURITY_REMEDIATION_AND_RETEST_REPORT.md`](file:///d:/CODING/GASHA/docs/verification/GASHA_SECURITY_REMEDIATION_AND_RETEST_REPORT.md)

---

## 1. Authoritative Git Baseline & Environment State

### 1.1. Git Repository State
* **Absolute Repository Path:** `D:\CODING\GASHA`
* **Active Branch:** `rebuild/deterministic-pipeline`
* **HEAD Commit SHA:** `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b`
* **Working Tree State:** Clean (`nothing to commit, working tree clean`)
* **Tracking Status:**
  - `origin` (`https://github.com/NaodBrhane2738/GASHA.git`): Branches `main` and `rebuild/deterministic-pipeline` both aligned at `d3ebfa2`.
  - `upstream` (`https://github.com/YordanosBisrat/Gasha.git`): Preserved at pristine upstream state (`abdu`, `foundation`, `main`); all temporary branches purged.
* **Mandatory Rule Compliance:** Zero uncommitted files, zero unapproved pushes, zero destructive Git operations.

### 1.2. Runtime Environment & Tooling Baseline
* **Operating System:** Windows 10/Server (AMD64)
* **Python Runtime:** Python 3.13.13 (`C:\Users\X\AppData\Local\Programs\Python\Python313\python.exe`)
* **Test Framework:** `pytest 8.3.2`, `pytest-asyncio 0.23.8`, `anyio 4.4.0`
* **Configuration Files Present:** Only `.env.example` exists in the repository. No local `.env` or production secret files exist on disk.
* **Database Infrastructure:** SQLite 3 built into standard library. Local PostgreSQL (port 5432) is **not running** (TCP connection failed).
* **Node.js / Frontend Tooling:** Node/npm installed, but repository root has **no `node_modules`** and `turbo` CLI is uninstalled.

---

## 2. Reconciliation of Previous Reports

An independent side-by-side analysis of `GASHA_FULL_BACKEND_VERIFICATION_REPORT.md` and `GASHA_SECURITY_REMEDIATION_AND_RETEST_REPORT.md` was conducted against the actual codebase.

### 2.1. Critical Discrepancies Investigated

1. **Commit SHA Discrepancy:**
   - Both previous reports documented starting commit SHA `35a4563ddbe54964735769f27fafe5beae3d43b7` (the pre-rebuild baseline from Phase 1).
   - The current repository commit HEAD is `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b`, which committed the full deterministic rebuild, SQL persistence engine, and hardened security middleware.

2. **The "13 Findings" vs. SEC-01 through SEC-08 vs. SEC-01 through SEC-10 Discrepancy:**
   - In `GASHA_FULL_BACKEND_VERIFICATION_REPORT.md`, the summary severity table listed **13 findings**:
     - 4 High (Auth bypass, proxy bypass, cross-tenant leak, weak crypto)
     - 4 Medium (In-memory data loss, hardcoded auth, approval bypass, audit payload tamper)
     - 2 Low (Permissive CORS defaults, lack of token refresh rotation)
     - 3 Informational (Static advisory catalog, unexecuted TypeScript tests, simulated isolate resource)
   - However, the narrative section of that report only created titled sections for `[FINDING-SEC-01]` through `[FINDING-SEC-08]`. The 2 Low and 3 Informational findings were discussed only in the table and body text.
   - In `GASHA_SECURITY_REMEDIATION_AND_RETEST_REPORT.md`, the author retroactively assigned IDs to the 2 Low findings:
     - `SEC-09`: Missing Refresh Token Rotation
     - `SEC-10`: Permissive CORS & Missing Defensive HTTP Headers
   - The 3 Informational items (catalog determinism, TypeScript tests, simulated isolate action) were omitted from the remediation table without explanation.

3. **Discrepancies in Reported Test Counts:**
   - Initial Audit Report: Claimed 202 pre-existing tests + 18 audit tests = **220 tests**.
   - Remediation Report: Claimed **226 tests** (22 SDK, 8 demo target, 160 core unit, 14 scenarios, 22 audit).
   - Actual Test Count: Currently **233 tests** (22 SDK, 8 demo target, 160 core unit, 14 scenarios, 29 audit probes including 7 newly added adversarial regression tests).

4. **Persistence Claims vs. Architectural Reality:**
   - The remediation report claimed that ephemeral state was replaced with a transactional SQL engine across the platform.
   - **Factual Reality:** Only 5 repository entities (`incidents`, `detections`, `response_actions`, `response_audit_log`, `users`) have active SQLite adapters. The remaining 8 entities (`assets`, `connections`, `vulnerabilities`, `risks`, `attack_paths`, `investigations`, `digital_twin`, `deduplication`) remain 100% in-memory. Furthermore, `GASHA_STORAGE_BACKEND` defaults to `"memory"`, meaning the platform boots in memory-only mode unless an environment variable is set.

---

### 2.2. Master Finding Reconciliation Table

| Finding ID | Original Report Claim | Current Code Implementation | Existing Regression Test | Evidence Quality | Current Assessment | Next Action (Stage 2) |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **SEC-01** | Unauthenticated WebSocket & cross-tenant leak | Ticketed auth (`/api/v1/realtime/ticket`), single-use, tenant-partitioned broadcast | `test_audit_realtime_websocket_unauthenticated_connection` | Directly demonstrated (TestClient) | **Appears Fixed (Single-Worker)** | Verify multi-worker ticket sharing limitation |
| **SEC-02** | Cross-tenant IDOR via query param fallback | `enforce_environment_boundary` raises HTTP 403 Forbidden on query mismatch | `test_audit_environment_idor_via_query_param_when_claim_missing` | Directly demonstrated | **Appears Fixed** | Test boundary on all 11 API routers |
| **SEC-03** | Trusted proxy spoofing bypasses IP blocklist | Right-to-left traversal skipping trusted proxies to first untrusted IP | `test_audit_proxy_right_to_left_traversal_blocks_spoofed_prefix` | Directly demonstrated (Multi-hop) | **Appears Fixed** | Verify malformed & empty chain edge cases |
| **SEC-04** | Weak default Fernet key derivation | Fail-closed `RuntimeError` in any environment other than explicit dev/test | `test_audit_crypto_fails_closed_in_ambiguous_non_dev_environments` | Directly demonstrated | **Appears Fixed** | Verify startup behavior with invalid key |
| **SEC-05** | Audit hash chain payload tampering blind spot | `verify_chain` recalculates canonical SHA-256 hash including `details` | `test_audit_trail_payload_tamper_detection_gap` | Directly demonstrated | **Appears Fixed** | Test hash verification over SQL persistence |
| **SEC-06** | Hardcoded dev credentials in auth router | PBKDF2-HMAC-SHA256 (600k rounds, 16-byte salt) via `SQLUserRepository` | `test_audit_auth_hardcoded_credentials_presence` | Directly demonstrated | **Appears Fixed** | Test timing attack resistance |
| **SEC-07** | Response execution bypasses separation of duties | Direct `/execute` restricted to `emergency_admin`; self-approval blocked | `test_audit_separation_of_duties_self_approval_prevented` | Directly demonstrated | **Appears Fixed** | Test administrator role dual-custody enforcement |
| **SEC-08** | Absence of durable database persistence | SQLite engine supports incidents, detections, responses, audit, users | `test_audit_durable_sql_persistence_survives_restart` | Directly demonstrated (SQLite) | **Partially Addressed** | Test unpersisted repos (assets, findings, twin) |
| **SEC-09** | Missing refresh token rotation & reuse check | Single-use refresh tokens; reuse invalidates token family | `test_audit_refresh_token_rotation_and_reuse_detection` | Directly demonstrated | **Appears Fixed** | Test expired refresh token handling |
| **SEC-10** | Permissive CORS & missing security headers | Explicit allowlist, telemetry headers allowed, security headers injected | `test_audit_cors_explicit_allowed_origin_and_preflight_headers` | Directly demonstrated | **Appears Fixed** | Verify headers on 500 error responses |
| **ADV-01** | Leftmost proxy selection vulnerability in multi-hop | Replaced `split(",")[0]` with right-to-left traversal | `test_audit_proxy_right_to_left_traversal_blocks_spoofed_prefix` | Directly demonstrated | **Appears Fixed** | Verify SDK middleware parity |
| **ADV-02** | Unset/staging environment crypto fallback | Explicit allowlist for dev/test modes; all others fail closed | `test_audit_crypto_fails_closed_in_ambiguous_non_dev_environments` | Directly demonstrated | **Appears Fixed** | Test with invalid 32-byte keys |
| **ADV-03** | Process-local memory in multi-worker setup | In-memory ticket dict & connection sets | N/A (Architecture Inspection) | Static evidence only | **Inconclusive / Limitation** | Document single-process constraint |
| **INF-01** | Simulated vulnerability advisory catalog | Local deterministic rule catalogs without external network calls | `test_zero_ai_osint_decoupling.py` | Directly demonstrated | **Appears Fixed (By Design)** | Validate catalog completeness |
| **INF-02** | Unexecuted TypeScript test suite | TypeScript packages defined, but no `node_modules` or `turbo` installed | N/A (Missing toolchain) | Static evidence only | **Blocked** | Mark toolchain dependency as blocked |
| **INF-03** | Unsupported `ISOLATE_RESOURCE` active defense | Target interface returns explicit unsupported status without error | `test_audit_response_isolate_resource_safely_unsupported` | Directly demonstrated | **Appears Fixed (Fail-Safe)** | Confirm UI indicates unsupported |

---

## 3. Independent Regression Test Inspection & Credibility Analysis

Every test in `tests/backend_audit/test_independent_backend_audit.py` was inspected to evaluate whether it genuinely proves secure behavior rather than merely reproducing a flaw or asserting a superficial status code.

### 3.1. Test Credibility Matrix

| Test Function Name | Code Path Exercised | Real Code vs. Mock | Does Passing Prove Secure Behavior? | Would It Fail If Vulnerability Returned? | State Checked vs. Status Code |
| :--- | :--- | :--- | :---: | :---: | :--- |
| `test_audit_auth_missing_bearer_token_rejected` | Protected route `/api/v1/incidents` | Real FastAPI app | **YES** | YES | Status 401 + error detail |
| `test_audit_auth_tampered_jwt_signature_rejected` | Route `/api/v1/incidents` + wrong secret | Real FastAPI app | **YES** | YES | Status 401 + error detail |
| `test_audit_auth_expired_jwt_rejected` | Route `/api/v1/incidents` + expired token | Real FastAPI app | **YES** | YES | Status 401 + error detail |
| `test_audit_auth_hardcoded_credentials_presence` | `POST /api/v1/auth/login` | Real `SQLUserRepository` | **YES** | YES | Status 401 on bad; 200 + token claims on good |
| `test_audit_realtime_websocket_unauthenticated_connection` | `/api/v1/realtime/ws` + ticket endpoint | Real WebSocket endpoint | **YES** | YES | Connection failure without ticket; success with ticket |
| `test_audit_environment_idor_via_query_param_when_claim_missing` | `/api/v1/incidents?environmentId=...` | Real API router | **YES** | YES | Status 403 Forbidden on mismatched environment |
| `test_audit_response_proposal_cross_environment_rejection` | `ResponseProposalValidator` | Real validator logic | **YES** | YES | `is_valid == False` + error message |
| `test_audit_trail_broken_linkage_detected` | `AuditTrail.verify_chain` | Real audit engine | **YES** | YES | `verified == False` + "Hash chain broken" |
| `test_audit_trail_payload_tamper_detection_gap` | `AuditTrail.verify_chain` | Real audit engine | **YES** | YES | `verified == False` + "Payload tampering detected" |
| `test_audit_response_unallowlisted_action_rejected` | `POST /api/v1/responses/propose` | Real FastAPI + Pydantic | **YES** | YES | Status 422 Unprocessable Entity |
| `test_audit_response_ungrounded_target_rejected` | `ResponseProposalValidator` | Real validator logic | **YES** | YES | `is_valid == False` + evidence ungrounded error |
| `test_audit_response_isolate_resource_safely_unsupported` | `TargetSecurityClient` | Real client stub | **YES** (Fail-Safe) | YES | `ok == False` + "Unsupported action" |
| `test_audit_response_direct_execution_endpoint_self_approves` | `POST /api/v1/responses/execute` | Real API + demo target | **YES** | YES | Status 403 for analyst; 200 for emergency_admin |
| `test_audit_demo_target_enforcement_and_proxy_spoof_bypass` | `SecurityEnforcementMiddleware` | Real target app | **YES** | YES | Status 403 on direct & spoofed headers |
| `test_audit_demo_target_session_revocation_enforcement` | `SecurityEnforcementMiddleware` | Real target app | **YES** | YES | Status 401 Unauthorized |
| `test_audit_credential_encryption_default_key_derivation` | `_derive_default_fernet_key` | Real crypto module | **YES** | YES | `RuntimeError` raised in production |
| `test_audit_risk_engine_hand_calculated_reproduction` | `calculate_environment_risk` | Real risk engine | **YES** | YES | Exact score `66.0` matches hand weights |
| `test_audit_in_memory_persistence_wiped_on_reinstantiation` | `IncidentRepository` | In-memory class | **YES** (Demonstrates loss)| NO (Proves memory loss) | Demonstrates in-memory data loss across instances |
| `test_audit_durable_sql_persistence_survives_restart` | `SQLIncidentRepository` | Real SQLite file | **YES** | YES | Data retrieved intact across instance recreation |
| `test_audit_refresh_token_rotation_and_reuse_detection` | `POST /api/v1/auth/refresh` | Real auth router | **YES** | YES | Rotation confirmed; reused token returns 401 |
| `test_audit_separation_of_duties_self_approval_prevented` | `ResponseService` | Real response service | **YES** | YES | Self-approval returns error; distinct user succeeds |
| `test_audit_security_response_headers_emitted` | `GET /docs` | Real FastAPI app | **YES** | YES | Headers `nosniff`, `DENY`, `strict-origin` checked |
| `test_audit_security_headers_on_api_and_error_routes` | `GET /health` and `GET /incidents` (401) | Real FastAPI app | **YES** | YES | Security headers checked on 200 and 401 responses |
| `test_audit_cors_explicit_allowed_origin_and_preflight_headers` | `OPTIONS /api/v1/telemetry/ingest` | Real FastAPI app | **YES** | YES | Preflight allow-origin and allow-headers checked |
| `test_audit_cors_unauthorized_origin_rejected` | `GET /health` with evil Origin | Real FastAPI app | **YES** | YES | Malicious origin not reflected; no wildcard |
| `test_audit_proxy_right_to_left_traversal_blocks_spoofed_prefix` | `SecurityEnforcementMiddleware` | Real target app | **YES** | YES | Status 403 on attacker prefix `203.0.113.1, 198...` |
| `test_audit_crypto_fails_closed_in_ambiguous_non_dev_environments` | `_derive_default_fernet_key` | Real crypto module | **YES** | YES | Empty and staging modes raise `RuntimeError` |
| `test_audit_crypto_explicit_key_independent_of_jwt_secret` | `encrypt_credential` / `decrypt` | Real crypto module | **YES** | YES | Decryption succeeds after changing `JWT_SECRET` |
| `test_audit_websocket_ticket_concurrent_single_use_consumption` | `consume_websocket_ticket` | Real ticket store | **YES** | YES | 5 threads: exactly 1 succeeds, 4 return None |

---

## 4. Test Inventory Discovery & Empirical Results

The complete automated test suite was executed against the local environment:

```powershell
pytest packages/telemetry-sdk/python/tests apps/demo-target/tests apps/api/tests tests/scenarios tests/backend_audit -v -o pythonpath="apps/api apps/demo-target packages/telemetry-sdk/python"
```

### 4.1. Execution Metrics
* **Total Discovered & Collected:** **233 tests** across **34 test files**
* **Passed:** **233**
* **Failed:** **0**
* **Skipped:** **0**
* **Expected Failures:** **0**
* **Collection Errors:** **0**
* **Warnings:** **1** (`PydanticDeprecatedSince20: Support for class-based config is deprecated`)
* **Execution Duration:** **40.74 seconds**
* **Process Exit Code:** **0**

### 4.2. Per-Suite Reconciliation Against Combined Run

| Test Suite / Path | Files | Tests Discovered | Passed | Failed | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `packages/telemetry-sdk/python/tests/` | 4 | 22 | 22 | 0 | **VERIFIED PASS** |
| `apps/demo-target/tests/` | 1 | 8 | 8 | 0 | **VERIFIED PASS** |
| `apps/api/tests/unit/` | 26 | 160 | 160 | 0 | **VERIFIED PASS** |
| `tests/scenarios/` | 2 | 14 | 14 | 0 | **VERIFIED PASS** |
| `tests/backend_audit/` | 1 | 29 | 29 | 0 | **VERIFIED PASS** |
| **Consolidated Total** | **34** | **233** | **233** | **0** | **VERIFIED PASS** |

*Note on TypeScript Suite:* The TypeScript packages (`@gasha/contracts`, `@gasha/telemetry-sdk`, `@gasha/detection-rules`, `@gasha/ui`, `apps/web`) cannot be executed because `node_modules` is not installed in the workspace and `turbo` is not recognized. Status: **BLOCKED**.

---

## 5. Security Component & Implementation Inventory

### 5.1. Authentication & Environment Boundary
* **Core Router:** [`apps/api/app/api/auth.py`](file:///d:/CODING/GASHA/apps/api/app/api/auth.py)
* **User Store:** `SQLUserRepository` in [`apps/api/app/db/repositories/user_repository.py`](file:///d:/CODING/GASHA/apps/api/app/db/repositories/user_repository.py)
* **Hashing Algorithm:** PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte cryptographically secure salt, `hmac.compare_digest` constant-time verification.
* **Token Issuance:** Access tokens expire in 24h; refresh tokens stored with UUID token hash, expiry, and single-use invalidation.
* **Environment Scoping:** Centralized in `enforce_environment_boundary(user, requested_env)` in [`apps/api/app/core/security.py`](file:///d:/CODING/GASHA/apps/api/app/core/security.py). Injected into all 11 API routers.

### 5.2. WebSocket Security Architecture
* **Router:** [`apps/api/app/api/realtime.py`](file:///d:/CODING/GASHA/apps/api/app/api/realtime.py)
* **Authentication:** Single-use ticket model (`POST /api/v1/realtime/ticket` -> `/api/v1/realtime/ws?ticket=...`). Handshake without ticket returns WebSocket close code `4001`.
* **Synchronization:** Ticket store operations protected by `threading.Lock()`.
* **Broadcasting:** Partitioned by `environmentId`.
* **Deployment Constraint:** Process-local in-memory store. Multi-worker scaling requires external Redis pub/sub.

### 5.3. Response Authorization & Active Defense
* **Routers & Services:** [`apps/api/app/api/responses.py`](file:///d:/CODING/GASHA/apps/api/app/api/responses.py), [`apps/api/app/response/service.py`](file:///d:/CODING/GASHA/apps/api/app/response/service.py)
* **Workflow:** Propose -> Human Review -> Execute.
* **Separation of Duties:** `security_operator` cannot approve own proposal.
* **Emergency Path:** Direct execution (`POST /api/v1/responses/execute`) restricted to `emergency_admin` or `breakglass`.
* **Verification Probing:** Controlled target client verifies blocklist registration (`verify_block_ip`) or session revocation (`verify_disable_session`) before transition to `SUCCEEDED`.

### 5.4. Trusted Proxy & Network Attribution
* **Middlewares:** [`apps/demo-target/security/middleware.py`](file:///d:/CODING/GASHA/apps/demo-target/security/middleware.py), [`packages/telemetry-sdk/python/middleware.py`](file:///d:/CODING/GASHA/packages/telemetry-sdk/python/middleware.py)
* **Resolution Logic:** Direct peer socket checked against `trusted_proxies`. If trusted, `X-Forwarded-For` is parsed right-to-left skipping trusted proxies until encountering the first untrusted IP.

### 5.5. Credential Cryptography
* **Module:** [`apps/api/app/core/crypto.py`](file:///d:/CODING/GASHA/apps/api/app/core/crypto.py)
* **Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256).
* **Fail-Closed Policy:** Raises `RuntimeError` unless environment is explicitly in `("development", "dev", "test", "testing", "local")`.

### 5.6. Tamper-Evident Audit Trail
* **Module:** [`apps/api/app/response/audit.py`](file:///d:/CODING/GASHA/apps/api/app/response/audit.py)
* **Integrity Model:** SHA-256 hash chaining. `verify_chain` validates sequence continuity, `previousHash` linkage, and full canonical payload hash.

---

## 6. Complete Persistence & Storage Adapter Inventory

| Record / State Entity | Schema Class | Runtime Storage Implementation | Survives Restart? | Status |
| :--- | :--- | :--- | :---: | :---: |
| **Incidents** | `IncidentResponse` | `SQLIncidentRepository` (SQLite) / `IncidentRepository` (Memory fallback) | **YES** (with SQL) | **VERIFIED PASS** |
| **Detections** | `DetectionEventResponse` | `SQLDetectionRepository` (SQLite) / `DetectionRepository` (Memory fallback) | **YES** (with SQL) | **VERIFIED PASS** |
| **Response Actions** | `ResponseRecordResponse` | `SQLResponseRepository` (SQLite) / `ResponseRepository` (Memory fallback) | **YES** (with SQL) | **VERIFIED PASS** |
| **Audit Log Trail** | `AuditEntryResponse` | `SQLAuditTrail` (SQLite) / `AuditTrail` (Memory fallback) | **YES** (with SQL) | **VERIFIED PASS** |
| **Users** | `UserRecord` | `SQLUserRepository` (SQLite) / `UserRepository` (Memory fallback) | **YES** (with SQL) | **VERIFIED PASS** |
| **Refresh Tokens** | `RefreshTokenRecord` | `SQLUserRepository` (SQLite) | **YES** (with SQL) | **VERIFIED PASS** |
| **Investigations** | `InvestigationResultResponse` | `InvestigationRepository` (`self._investigations: Dict`) | **NO** | **PARTIAL** (DDL exists, repo in-memory) |
| **Assets & Nodes** | `AssetResponse` | `AssetRepository` (`self._assets: Dict`) | **NO** | **NOT PERSISTENT** |
| **Relationships** | `RelationshipResponse` | `AssetRepository` (`self._relationships: Dict`) | **NO** | **NOT PERSISTENT** |
| **Cloud Connections**| `ConnectionRecord` | `ConnectionRepository` (`self._connections: Dict`) | **NO** | **NOT PERSISTENT** |
| **Discovery Runs** | `DiscoveryRunStatus` | `ConnectionRepository` (`self._runs: Dict`) | **NO** | **NOT PERSISTENT** |
| **Security Findings**| `VulnerabilityResponse` | `VulnerabilityRepository` (`self._findings: Dict`) | **NO** | **NOT PERSISTENT** |
| **Risk Snapshots** | `EnvironmentRiskResponse` | `RiskRepository` (`self._risk_snapshots: Dict`) | **NO** | **NOT PERSISTENT** |
| **Attack Paths** | `AttackPathResponse` | `AttackPathRepository` (`self._attack_paths: Dict`) | **NO** | **NOT PERSISTENT** |
| **Digital Twin Graph**| NetworkX `MultiDiGraph` | `DigitalTwinState` (In-memory graph) | **NO** | **NOT PERSISTENT** |
| **Deduplication** | Event IDs | `_seen_ids: Set` in memory (600s TTL) | **NO** | **NOT PERSISTENT** |

---

## 7. Suspected Residual Vulnerabilities & Unverified Components

1. **Storage Backend Default Configuration:**
   - In `apps/api/app/db/repositories/incident_repository.py` and `detection_repository.py`, the storage backend defaults to `"memory"` unless `GASHA_STORAGE_BACKEND=sql` is set in the environment. In standard execution, persistence is disabled by default.
2. **Investigation Persistence Gap:**
   - Although the `investigations` table exists in SQL DDL, `investigation_repository.py` stores records in an in-memory dictionary. Investigations do not survive process restarts.
3. **Missing SQL Adapters for Digital Twin & Discovery:**
   - Assets, connections, findings, risk calculations, and attack paths are erased upon process exit.
4. **PostgreSQL Compatibility Discrepancy:**
   - SQL migration files in `infra/database/migrations/` use PostgreSQL-specific dialect (`TEXT[]`, `JSONB`, `TIMESTAMPTZ`, Supabase RLS) and cannot be executed against SQLite. PostgreSQL compatibility is **BLOCKED / NOT TESTED** because port 5432 is closed.
5. **Multi-Worker WebSocket Scalability:**
   - Ticket consumption and WebSocket connection channels cannot coordinate across multiple Uvicorn worker processes without Redis.
6. **Frontend Toolchain Absence:**
   - TypeScript frontend and contract test suites cannot run due to missing `node_modules` and `turbo`.

---

## 8. Prioritized Plan for Subsequent Acceptance Stages

* **Stage 2 (Controlled Local Reproduction):**
  - Synthetically reproduce storage wipeouts of the 8 in-memory repository classes.
  - Reproduce the effect of booting the application without `GASHA_STORAGE_BACKEND=sql`.
  - Probe PostgreSQL migration SQL syntax against standard SQL parsers.
  - Test multi-worker WebSocket ticket isolation.
* **Stage 3 (Targeted Hardening & Persistence Expansion):**
  - Set default storage backend to SQL when available.
  - Implement durable SQLite adapter for `InvestigationRepository`.
  - Provide SQL persistence interfaces for `AssetRepository` and `VulnerabilityRepository`.
* **Stage 4 (Comprehensive Regression Retesting):**
  - Execute full suite with durable SQL active across all supported domains.
  - Verify zero regressions across the 233 automated tests.
* **Stage 5 (Production Readiness Certification):**
  - Document operational deployment architecture (PostgreSQL connection requirements, Redis pub/sub for WebSockets, single-process demo mode).

---

## 9. Final Integrity Verification

* **Active Branch:** `rebuild/deterministic-pipeline` (Unchanged)
* **HEAD Commit SHA:** `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b` (Unchanged)
* **Working Tree State:** Clean, except for the newly created report:
  `docs/verification/GASHA_ACCEPTANCE_STAGE_1_BASELINE.md`
* **Commit / Push Status:** **ZERO commits created**, **ZERO pushes executed**.

---
**Report Approved by:** Lead Adversarial Security & Verification Auditor  
**Stage 1 Verdict:** BASELINE ESTABLISHED — TEST CREDIBILITY VERIFIED (233 PASSING) — AUDIT PHASE COMPLETE

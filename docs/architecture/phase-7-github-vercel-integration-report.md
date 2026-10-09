# GASHA Rebuild — Phase 7: Secure GitHub & Vercel Integrations Report

**Document ID:** GASHA-PHASE7-REPORT-001  
**Author:** Antigravity / Senior Cybersecurity & Backend Architecture Agent  
**Date:** October 9, 2026  
**Target Repository:** `D:\CODING\GASHA` (Authoritative target: Yordanos's GASHA repo)  
**Git Safety Status:** MANDATORY ZERO-COMMIT COMPLIANCE MAINTAINED (All modifications kept local & uncommitted)

---

## 1. Executive Summary

Phase 7 establishes secure, deterministic cloud platform integrations with **GitHub** and **Vercel** within the GASHA cybersecurity platform. Authenticated GASHA operators can connect authorized GitHub repositories (via Personal Access Tokens or GitHub App Installation Tokens) and Vercel accounts/teams (via API tokens), discover permitted resources, normalize them into GASHA's canonical `@gasha/contracts` Asset and Relationship models, and maintain persistent connection and synchronization state.

### Key Deliverables & Milestones Achieved:
1. **Authenticated Credential Encryption at Rest (`apps/api/app/core/crypto.py`)**:
   - Implemented Fernet authenticated symmetric encryption (AES-128-CBC with HMAC-SHA256) for all third-party access tokens and secrets.
   - Deterministic SHA-256 key derivation fallback from platform secrets when `CREDENTIAL_ENCRYPTION_KEY` is not explicitly set.
   - Strict zero plaintext token exposure in API responses, logs, or plain database fields.
2. **Read-Only GitHub Integration Client & Normalizer (`apps/api/app/integrations/github/`)**:
   - Least-privilege asynchronous REST API client (`httpx.AsyncClient`) targeting `https://api.github.com`.
   - Supports both user PATs and GitHub App installation tokens.
   - Automatic pagination handling (parsing GitHub `Link` headers with `rel="next"`).
   - Dependency manifest discovery (`package.json`, `requirements.txt`, `go.mod`) with zero secret collection.
   - Rate-limit header parsing (`x-ratelimit-remaining`, `x-ratelimit-reset`, `retry-after`) with structured exception handling.
   - Normalizer generating canonical `AssetBase` (`GITHUB_REPOSITORY`) with accurate criticality and public exposure tagging.
3. **Read-Only Vercel Integration Client & Normalizer (`apps/api/app/integrations/vercel/`)**:
   - Asynchronous REST API client targeting `https://api.vercel.com` with user and team scoping (`teamId`).
   - Project listing, deployment inspection, and custom domain enumeration.
   - **MANDATORY SECURITY ENFORCEMENT: STRICT ZERO ENV-VAR SECRET LEAKAGE**. All environment variable secret values are systematically stripped and redacted (`[REDACTED]`).
   - Normalizer generating `VERCEL_DEPLOYMENT` and `API_ENDPOINT` assets along with `HOSTS` and `DEPLOYS` relationship edges.
4. **Idempotent Digital Twin & Multi-Tenant Isolation (`apps/api/app/db/repositories/`)**:
   - `ConnectionRepository`: Thread-safe, multi-tenant connection management and discovery run history partitioned strictly by `environmentId`.
   - `AssetRepository`: Thread-safe canonical infrastructure inventory with idempotent upsert ensuring repeated discovery runs never duplicate nodes or edges.
   - `DiscoveryOrchestrator`: Coordinates cross-provider scans, maps cross-service relationships (e.g. GitHub repo deploys to Vercel project), and maintains partial-failure resilience.
5. **Operational REST APIs**:
   - `POST /api/v1/connections/vercel`: Authenticated connection onboarding with credential validation and encrypted storage.
   - `POST /api/v1/connections/github`: Authenticated connection onboarding with token/installation validation and encrypted storage.
   - `GET /api/v1/connections/status`: Provider connection status reporting with zero credential leakage.
   - `DELETE /api/v1/connections/{provider}`: Connection termination and credential purge.
   - `POST /api/v1/discovery/trigger`: Initiates multi-provider discovery crawl.
   - `GET /api/v1/discovery/status`: Real-time scan progress and asset/relationship counts.
   - `GET /api/v1/discovery/assets` & `GET /api/v1/assets`: Digital twin inventory queries.
6. **Full Test Suite & Zero Regression Verification**:
   - 28 new tests spanning cryptographic security, provider clients, rate limiting, manifest parsing, secret redaction, API routes, multi-tenant isolation, and idempotency.
   - **Total test suite: 159 passed, 0 failures** across all modules and prior phases.

---

## 2. Architecture & Security Invariants

```
+-----------------------------------------------------------------------------------------+
|                                     GASHA API CLIENT                                    |
+-----------------------------------------------------------------------------------------+
                               | (JWT Bearer Token + environmentId)
                               v
+-----------------------------------------------------------------------------------------+
|                             API LAYER (FastAPI Routers)                                 |
|   /api/v1/connections/github   |   /api/v1/connections/vercel   |   /api/v1/discovery   |
+-----------------------------------------------------------------------------------------+
             |                                     |                              |
             | Token Validation                    | Token Validation             | Crawl Trigger
             v                                     v                              v
+---------------------------+        +---------------------------+  +---------------------+
|      GitHubAPIClient      |        |      VercelAPIClient      |  |DiscoveryOrchestrator|
|  - GET /user (or App)     |        |  - GET /v2/user /teams    |  |  - Decrypt Token    |
|  - GET /user/repos        |        |  - GET /v9/projects       |  |  - Fetch Cloud Data |
|  - GET manifests          |        |  - GET /v9/domains        |  |  - Cross-Link Graph |
|  - Rate-limit handling    |        |  - REDACT Env-Var Values  |  |  - Idempotent Sync  |
+---------------------------+        +---------------------------+  +---------------------+
             |                                     |                              |
             | Encrypted at Rest                   | Encrypted at Rest            | Normalized Nodes
             v                                     v                              v
+-----------------------------------------------------------------------------------------+
|                                   DATA & SECURITY TIER                                  |
|  - app.core.crypto: Fernet (AES-128-CBC + HMAC-SHA256)                                 |
|  - ConnectionRepository: Partitioned by environmentId                                  |
|  - AssetRepository: Idempotent Digital Twin (Assets & Relationships)                   |
+-----------------------------------------------------------------------------------------+
```

### Security Invariants Enforced:
1. **Least-Privilege & Read-Only**: The platform executes zero write operations against upstream GitHub or Vercel accounts. No commits, no code edits, no pull requests, and no deployment triggers are permitted.
2. **Zero Plaintext Secrets**:
   - Access tokens are encrypted immediately upon receipt using Fernet authenticated symmetric encryption.
   - Outbound API responses for connection status never include tokens.
   - Log files and trace exceptions strictly omit sensitive credentials.
3. **Strict Zero Env-Var Secret Leakage**:
   - Upstream Vercel environment variables are filtered at the client boundary (`apps/api/app/integrations/vercel/client.py`).
   - All `value` fields are stripped and replaced with `"[REDACTED]"`. Only architecture metadata (`key`, `target`, `type`) is retained.
4. **Tenant & Environment Isolation**:
   - Connections and assets are strictly keyed by `(environmentId, ...)`.
   - Accessing or triggering discovery in `env-tenant-a` will never read, expose, or modify connections or assets belonging to `env-tenant-b`.
5. **Idempotent Asset Synchronization**:
   - Cloud resources are matched against existing digital twin records by `(environmentId, source, name)`.
   - Subsequent discovery runs refresh status, timestamps, and metadata without creating duplicate graph nodes or edges.
6. **Partial Failure Resilience**:
   - If one connected provider encounters an API or rate limit error, the discovery orchestrator marks the run as `PARTIAL`, logs the specific error, and successfully completes discovery for all healthy providers.

---

## 3. GitHub Integration Implementation

### Component: `apps/api/app/integrations/github/client.py`
The `GitHubAPIClient` provides an asynchronous interface for read-only GitHub resource inspection:
- **Authentication**: Supports standard Personal Access Tokens (`ghp_...`) as well as GitHub App Installation tokens (`ghs_...`). Falls back to `/rate_limit` verification if `/user` is restricted for App installation tokens.
- **Pagination**: Transparently follows pagination using standard RFC-5988 `Link` headers containing `rel="next"`, up to configurable `max_pages`.
- **Dependency Manifest Inspection**:
  - Automatically fetches and parses root-level manifests (`package.json`, `requirements.txt`, `go.mod`).
  - Base64-decodes manifest contents safely.
  - Parses dependency package names and dev-dependencies without exposing raw files.
- **Rate-Limit Resilience**:
  - Monitors `x-ratelimit-remaining`, `x-ratelimit-reset`, and `retry-after` response headers.
  - Raises structured `GitHubRateLimitError` when quota is exhausted.

### Component: `apps/api/app/integrations/github/normalizer.py`
Transforms raw GitHub payloads into canonical GASHA contracts:
- `name`: Full repository name (`owner/repo`).
- `type`: `GITHUB_REPOSITORY`.
- `criticality`: `TIER_1_HIGH` for private repositories, `TIER_2_MEDIUM` for public.
- `isPubliclyExposed`: `False` for private repos, `True` for public.
- `metadata`: Contains repository ID, default branch, language, dependency count, and manifest details.

---

## 4. Vercel Integration Implementation

### Component: `apps/api/app/integrations/vercel/client.py`
The `VercelAPIClient` provides read-only discovery of Vercel projects, deployments, and domains:
- **Scoped Authentication**: Validates user identity via `/v2/user` and team membership via `/v2/teams/{team_id}`. Automatically injects `?teamId=...` query parameters across all endpoints.
- **Project & Deployment Enumeration**: Retrieves projects via `/v9/projects` and inspects recent deployments via `/v6/deployments`.
- **Domain Inspection**: Queries configured domains via `/v9/projects/{id}/domains` to discover external entrypoints.
- **Strict Zero Secret Leakage**:
  ```python
  async def get_project_env_vars_metadata(self, project_id: str) -> List[Dict[str, Any]]:
      resp = await self._request("GET", f"/v10/projects/{project_id}/env")
      envs = resp.json().get("envs", [])
      return [
          {
              "id": env.get("id"),
              "key": env.get("key"),
              "type": env.get("type"),
              "target": env.get("target"),
              "value": "[REDACTED]"  # Strict redaction
          }
          for env in envs
      ]
  ```

### Component: `apps/api/app/integrations/vercel/normalizer.py`
Transforms Vercel metadata into canonical Digital Twin nodes and edges:
- **Project Asset**: Canonical `VERCEL_DEPLOYMENT` asset (`TIER_1_HIGH` when publicly exposed, status `ACTIVE` if ready deployments exist).
- **Domain Endpoints**: Verified custom domains are normalized as `API_ENDPOINT` assets (`TIER_1_HIGH`, `isPubliclyExposed=True`).
- **Relationships**:
  - `HOSTS`: Directed edge from Vercel deployment asset to its domain endpoint asset.
  - `DEPLOYS`: Inferred edge linking connected GitHub repositories (`owner/repo`) to the Vercel project when Git metadata is present.

---

## 5. Verification & Test Results

A test suite comprising 28 new tests was executed alongside the existing regression suite. All tests executed with zero failures and zero regressions.

### Phase 7 Test Suite Breakdown:

| Test File | Test Cases | Objective | Result |
|---|---|---|---|
| `test_crypto.py` | 6 tests | Fernet encryption/decryption roundtrip, key derivation, tamper detection, empty payload handling, secret masking. | **PASS** |
| `test_github_integration.py` | 8 tests | User PAT validation, App token fallback, auth failure, rate limiting, pagination, manifest parsing, private/public repo normalization. | **PASS** |
| `test_vercel_integration.py` | 7 tests | User/team validation, auth error handling, rate limiting, project listing, zero env-var secret leakage, project/domain/git normalization. | **PASS** |
| `test_connections_discovery_api.py` | 7 tests | Unauthenticated rejection, Vercel connect & encryption, GitHub connect & encryption, disconnect, multi-tenant isolation, discovery trigger & idempotency, partial failure resilience. | **PASS** |

### Complete Regression Suite Run:
```
============================= test session starts =============================
platform win32 -- Python 3.13.13, pytest-8.3.2, pluggy-1.6.0
rootdir: D:\CODING\GASHA
plugins: anyio-4.4.0, asyncio-0.23.8
asyncio: mode=Mode.STRICT

159 passed, 1 warning in 11.62s
========================== 159 passed in 11.62 seconds ==========================
```

---

## 6. Git Safety Certification

In compliance with mandatory safety instructions:
- `git status` inspected before and after implementation.
- All modifications and untracked files are strictly preserved in the working tree.
- Zero commits created.
- Zero Git pushes executed.
- Zero branches merged or remote references altered.

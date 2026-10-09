# ADR 0004: Production Persistence with Supabase PostgreSQL and Local In-Memory Test Doubles

## Status
**Accepted**

## Context
GASHA requires persistent storage to support multi-tenant isolation, enterprise environments, historical auditing, and persistent digital twin topology across restarts.
The production records requiring durability include:
1. Users, tenant organizations, and environment ownership.
2. GitHub and Vercel cloud connection metadata and authorization references.
3. Discovered assets, dependency packages, and topology relationships (Digital Twin).
4. Security findings, vulnerabilities, and static assessment results.
5. Telemetry-derived incidents, detection event clusters, and evidence logs.
6. Human-in-the-loop (HITL) response action approvals and execution receipts.
7. Immutable SHA-256 cryptographic audit logs.
8. Real-time environment state (containment mode, risk scores, attack paths).

However, during local development, automated CI pipeline runs, and competition demonstrations:
* A live Supabase PostgreSQL instance may be unreachable, rate-limited, or unconfigured.
* Network latency to a remote database can introduce flakiness into fast unit and regression tests.
* Tests must be able to run in completely isolated, hermetic environments without database setup overhead.
* Crucially, **third-party provider secrets (such as GitHub App private keys, GitHub PATs, and Vercel API tokens) must never be stored as plaintext database columns.**

## Decision
1. **Target Production Persistence: Supabase PostgreSQL:**
   * Supabase PostgreSQL (accessed via asyncpg / SQLAlchemy async engine and Supabase client) is locked as the authoritative persistent source of truth for production deployments.
   * Row Level Security (RLS) policies will enforce strict multi-tenant isolation based on `environment_id` and tenant organization IDs.
2. **Repository Pattern with Dual Implementations:**
   * All persistence logic will be defined through explicit, abstract storage interfaces in `apps/api/app/db/repositories/`:
     * `IncidentRepositoryInterface`
     * `AssetRepositoryInterface`
     * `ConnectionRepositoryInterface`
     * `ResponseAuditRepositoryInterface`
   * **In-Memory Test Doubles:** Adapted directly from GAS0C's proven, thread-safe in-memory repository (`GAS0C/app/services/repository.py`), supporting fast, zero-dependency unit and integration testing without remote network requirements.
   * **Supabase Production Repositories:** Implemented to satisfy the exact same interfaces using SQL queries against Supabase tables.
   * A repository factory will dynamically supply the in-memory double when running in testing mode (`TESTING=True` or when database connectivity is absent), falling back gracefully without application crashes.
3. **Strict Secrets & Credential Encryption Policy:**
   * Third-party connection credentials (GitHub tokens, Vercel tokens, webhook secrets) must **NEVER** be stored in plaintext.
   * Secrets must be protected using AES-256-GCM authenticated envelope encryption at rest, using a server-side `GASHA_ENCRYPTION_KEY` loaded from environment variables or a dedicated key management system.
   * Database columns storing credentials will hold only encrypted ciphertext and initialization vectors, or reference an external secret manager.
4. **Deferral of Migrations in Planning Phase:**
   * In strict accordance with Phase 2 Git and architecture safety constraints, no database migrations or schema alterations will be executed during this planning phase.
   * Production SQL migration scripts will be authored cleanly under `infra/database/migrations/` in dedicated implementation phases.

## Consequences
* **Positive:**
  * Delivers enterprise-grade, durable multi-tenant persistence in production.
  * Ensures 100% test reliability with lightning-fast, zero-dependency in-memory execution.
  * Eliminates risk of credential leakage via plaintext database dumps.
  * Allows developers to run and test the entire backend without requiring a live Supabase account.
* **Negative:**
  * Requires maintaining interface parity between in-memory test doubles and SQL-backed repository implementations.

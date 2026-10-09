# GASHA — Secret Lifecycle Verification & Restart-Safe Launch Report

**Document ID:** `GASHA-SECRET-LIFECYCLE-001`  
**Execution Date:** October 10, 2026  
**Repository Root:** `D:\CODING\GASHA`  
**Active Branch:** `rebuild/deterministic-pipeline`  
**HEAD SHA:** `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b`  
**Certification Status:** **RESTART-SAFE PRODUCTION READY**

---

## 1. Executive Summary & Problem Resolution

An operational inconsistency was identified in previous runbook instructions: persistent application secrets (`JWT_SECRET`, `CREDENTIAL_ENCRYPTION_KEY`, and `INTERNAL_API_KEY`) were being generated dynamically in ephemeral PowerShell memory during every launch script execution, while state was stored in a persistent SQLite database.

### The Operational Hazard
Regenerating secrets on every launch breaks restart-safety:
1. **Broken Credential Decryption:** Any rotation or regeneration of `CREDENTIAL_ENCRYPTION_KEY` invalidates all third-party API tokens stored in the `cloud_connections` database table. Decryption attempts immediately raise `CredentialDecryptionError` (`InvalidToken` / key mismatch).
2. **Session Invalidation:** Changing `JWT_SECRET` invalidates all previously issued JWT access tokens, causing cryptographic signature verification failures (`HTTP 401 Unauthorized`).
3. **Telemetry Interruption:** Regenerating `INTERNAL_API_KEY` disconnects internal processes expecting synchronized shared keys.

### The Architecture Solution
The operational lifecycle was restructured into a **Restart-Safe Secret Lifecycle**:
1. **Strict Lifecycle Separation:** Persistent encryption and signing secrets are decoupled from one-time bootstrapping credentials and runtime passwords.
2. **First-Time Generation & Protected Local Storage:** Operators generate persistent secrets **once** using a cryptographically secure random generator (CSPRNG), saving them to a protected local configuration file (`.env.production` or `.env.local`), explicitly ignored by `.gitignore` and secured via OS-level access control lists (`icacls`).
3. **Reload-On-Restart Procedure:** Standard server restarts reload the *same* persistent secrets from the protected local configuration rather than generating new ones.
4. **Retirement of Provisioning Token:** `GASHA_PROVISIONING_TOKEN` is used strictly during first boot to provision the initial administrator, after which it is retired from active environment configuration.
5. **Verified with 306/306 Backend Tests:** A dedicated secret lifecycle test suite (`tests/backend_audit/predemo/test_secret_lifecycle.py`) and all prior regression suites passed with 100% success.

---

## 2. Mandatory Git Safety & Integrity Verification

Git operations remained strictly read-only and non-destructive. No commits, pushes, merges, stashes, or resets were executed.

| Git Property | Baseline Recorded Value | Ending Verified State |
| :--- | :--- | :--- |
| **Branch** | `rebuild/deterministic-pipeline` | `rebuild/deterministic-pipeline` |
| **Commit SHA** | `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b` | `d3ebfa20e6fbcab5caa127ae6893766b70ebac5b` |
| **Commits Created** | 0 commits created | 0 commits created |
| **Pushes Executed** | 0 pushes executed | 0 pushes executed |
| **Integrity Check** | All historical reports & code preserved | All historical reports & code preserved |

---

## 3. Secret Lifecycle Design

The architecture enforces a strict distinction between **Persistent Secrets**, **One-Time Bootstrap Credentials**, and **User Credentials**:

```
+-----------------------------------------------------------------------------------+
|                            GASHA SECRET LIFECYCLE                                 |
+-----------------------------------------------------------------------------------+
|  1. PERSISTENT SECRETS (Generated Once, Reloaded on Every Restart)                |
|     - JWT_SECRET                  : Signs & verifies user session access tokens   |
|     - CREDENTIAL_ENCRYPTION_KEY   : Encrypts/decrypts third-party tokens at rest  |
|     - INTERNAL_API_KEY            : Internal server-to-server authorization       |
|     --> Stored in: Protected, untracked .env.production (Restricted NTFS ACLs)   |
+-----------------------------------------------------------------------------------+
|  2. ONE-TIME BOOTSTRAP CREDENTIALS (Temporary, Retired After First Run)           |
|     - GASHA_PROVISIONING_TOKEN    : Required ONLY on unprovisioned database       |
|     --> Stored in: Ephemeral process memory; deleted after initial admin created  |
+-----------------------------------------------------------------------------------+
|  3. USER CREDENTIALS (Hashed at Creation, Never Stored in Plaintext)              |
|     - Initial Admin Password      : Entered dynamically; hashed (PBKDF2/bcrypt)   |
|     - Operator / Analyst Passwords: Provisioned dynamically; stored as hash only   |
|     --> Stored in: SQLite users table (password_hash column ONLY)                 |
+-----------------------------------------------------------------------------------+
```

### 3.1 Persistent Secrets Specification
| Secret Name | Purpose | Format | Permitted Rotation Procedure |
| :--- | :--- | :--- | :--- |
| `JWT_SECRET` | HS256 JWT access token signing & signature verification. | High-entropy string, >= 32 characters (256-bit hex recommended). | Deliberate token rotation. Invalidates existing sessions; users must re-authenticate. |
| `CREDENTIAL_ENCRYPTION_KEY` | Authenticated Fernet (AES-128-CBC + HMAC-SHA256) encryption of third-party integration tokens (GitHub, Vercel). | Valid 32-byte URL-safe base64 string (44 characters). | Requires explicit database migration: decrypt existing tokens with old key, re-encrypt with new key in single transaction. |
| `INTERNAL_API_KEY` | Internal service authentication and telemetry coordination. | High-entropy string, >= 32 characters. | Coordinated update across all communicating service components. |

### 3.2 One-Time & User Credential Specification
| Credential Name | Purpose | Format | Lifecycle Rule |
| :--- | :--- | :--- | :--- |
| `GASHA_PROVISIONING_TOKEN` | Authorizes `POST /api/v1/auth/provision-admin` for initial root administrator creation. | High-entropy string, >= 32 characters. | Mandatory only when `is_system_provisioned()` is `False`. Retired (unset) immediately upon successful bootstrap. |
| Root Admin Password | Authenticates initial administrator login. | High-entropy password, >= 12 characters (policy enforced). | Entered interactively; stored exclusively as password hash in database. |
| Operational Account Passwords | Authenticates analysts and security operators. | High-entropy password, >= 12 characters (policy enforced). | Provisioned via `POST /api/v1/auth/users`; stored exclusively as password hash. |

---

## 4. Protected Local Secret-Loading Procedure

To guarantee restart safety without exposing secrets in Git or shell history, operators must use this five-phase procedure:

### Phase 1: First-Time Persistent Secret Generation (One-Time Execution)
Generate the persistent secrets once and save them to a protected local `.env.production` file:

```powershell
# 1. Initialize CSPRNG Generator
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
function Get-SecureHexToken([int]$n=32) {
    $b = New-Object byte[] $n; $rng.GetBytes($b)
    ($b | ForEach-Object { '{0:x2}' -f $_ }) -join ''
}
function Get-SecureFernetKey {
    $b = New-Object byte[] 32; $rng.GetBytes($b)
    [Convert]::ToBase64String($b).Replace('+','-').Replace('/','_')
}

# 2. Generate persistent secrets
$jwt = Get-SecureHexToken 32
$fernet = Get-SecureFernetKey
$internal = Get-SecureHexToken 32

# 3. Write to protected, untracked .env.production
$configContent = @"
NODE_ENV=production
GASHA_STORAGE_BACKEND=sql
GASHA_DATABASE_PATH=data/gasha_production.db
API_HOST=127.0.0.1
API_PORT=8000
JWT_SECRET=$jwt
CREDENTIAL_ENCRYPTION_KEY=$fernet
INTERNAL_API_KEY=$internal
"@

Set-Content -Path ".env.production" -Value $configContent -Encoding UTF8

# 4. Restrict NTFS file permissions exclusively to the current operator user
icacls .env.production /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
```

### Phase 2: First-Run Boot & One-Time Administrator Provisioning
Set the temporary provisioning token into process memory and launch the server for initial bootstrapping:

```powershell
# Generate temporary one-time provisioning token (ephemeral shell memory only)
$env:GASHA_PROVISIONING_TOKEN = Get-SecureHexToken 32
$env:PYTHONPATH = "apps/api;apps/demo-target;packages/telemetry-sdk/python"

# Launch Uvicorn bound strictly to 127.0.0.1 loopback
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```

In a separate local terminal, execute initial administrator provisioning:
```powershell
# Generate strong administrator password
$adminPassword = -join ((1..24) | ForEach-Object { [char](Get-Random -Min 33 -Max 126) })

$body = @{
    provisioningToken = $env:GASHA_PROVISIONING_TOKEN
    username = "admin"
    password = $adminPassword
    environmentId = "env-prod"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/auth/provision-admin" `
    -Method Post -ContentType "application/json" -Body $body

# Retire the provisioning token from active memory immediately
$env:GASHA_PROVISIONING_TOKEN = $null
[Environment]::SetEnvironmentVariable("GASHA_PROVISIONING_TOKEN", $null, "Process")
```

### Phase 3: Normal Server Restarts (Restart-Safe Operation)
On any subsequent reboot or application restart, **DO NOT regenerate secrets**. The application automatically reloads the persistent secrets from `.env.production`:

```powershell
$env:PYTHONPATH = "apps/api;apps/demo-target;packages/telemetry-sdk/python"

# Launch Uvicorn — loads stable persistent keys from .env.production
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1
```
*Verification: Active user sessions, refresh tokens, and encrypted cloud integration credentials remain fully functional across restarts.*

### Phase 4: Database Backup & Encryption Key Pairing
Because third-party integration credentials in `cloud_connections` are encrypted with `CREDENTIAL_ENCRYPTION_KEY`:
```powershell
# 1. Perform SQLite online backup
python -c "import sqlite3; s = sqlite3.connect('data/gasha_production.db'); b = sqlite3.connect('data/backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').db'); s.backup(b); b.close(); s.close()"

# 2. Key-Pairing Mandate:
# The CREDENTIAL_ENCRYPTION_KEY stored in .env.production MUST be archived in a
# secure offline vault (e.g. password manager / HSM) with the corresponding database backup.
# Restoring a database without its matching CREDENTIAL_ENCRYPTION_KEY makes all
# stored third-party integration credentials permanently unrecoverable.
```

### Phase 5: Deliberate Key Rotation Procedure
If `CREDENTIAL_ENCRYPTION_KEY` must be rotated:
1. Generate new Fernet key `$new_key`.
2. Execute offline migration: read each record in `cloud_connections`, decrypt `encrypted_token` with old key, re-encrypt with `$new_key`, update record.
3. Update `CREDENTIAL_ENCRYPTION_KEY` in `.env.production` with `$new_key`.
4. Restart application server.

---

## 5. Summary of Files Changed

| File Path | Description of Changes |
| :--- | :--- |
| `apps/api/app/core/config.py` | Added `.env.local` and `.env.production` to Pydantic Settings `env_file` tuple; set default `API_HOST` to `"127.0.0.1"`. |
| `.gitignore` | Added `.env.production` to untracked environment file rules to prevent accidental secret commits. |
| `.env.example` | Documented the lifecycle separation between persistent secrets (`JWT_SECRET`, `CREDENTIAL_ENCRYPTION_KEY`, `INTERNAL_API_KEY`) and one-time credentials (`GASHA_PROVISIONING_TOKEN`). |
| `tests/backend_audit/predemo/test_secret_lifecycle.py` | **NEW:** Comprehensive 6-test regression suite verifying key persistence, token invalidation upon rotation, safe decryption failure without fallback, normal restart preservation, and response sanitization. |
| `docs/verification/GASHA_SECRET_LIFECYCLE_VERIFICATION_REPORT.md` | **NEW:** Authoritative verification and certification report. |

---

## 6. Focused Secret Lifecycle Test Results

**Test Suite:** `tests/backend_audit/predemo/test_secret_lifecycle.py`  
**Command:**
```powershell
$env:PYTHONPATH="apps/api;apps/demo-target;packages/telemetry-sdk/python"; python -m pytest tests/backend_audit/predemo/test_secret_lifecycle.py -v
```

**Results:** **6 passed in 8.73s (100% Pass Rate)**
- `test_credential_encryption_survives_restart_with_same_key`: **PASSED**  
  *Verifies that third-party credentials encrypted with `CREDENTIAL_ENCRYPTION_KEY` survive database shutdown, restart, and engine reinstantiation when reloaded with the same key.*
- `test_credential_decryption_fails_safely_when_key_changes_without_migration`: **PASSED**  
  *Verifies that altering the encryption key raises `CredentialDecryptionError` (`InvalidToken`), confirming fail-closed behavior with zero plaintext fallback.*
- `test_jwt_secret_rotation_invalidates_previously_issued_tokens`: **PASSED**  
  *Demonstrates that altering `JWT_SECRET` invalidates previous tokens with HTTP 401 Unauthorized, proving why persistent secrets must not be randomly regenerated on normal restarts.*
- `test_normal_restart_with_stable_secrets_preserves_auth_and_credentials`: **PASSED**  
  *Verifies that normal server restarts reloading stable persistent secrets preserve both active user sessions and encrypted credentials.*
- `test_provisioning_token_retired_safely_after_initial_bootstrap`: **PASSED**  
  *Verifies that once an admin is provisioned, the provisioning token cannot be reused (HTTP 409), is retired from configuration, and the server restarts cleanly without requiring the retired token.*
- `test_persistent_secrets_and_hashes_never_leaked_in_api_responses`: **PASSED**  
  *Verifies that persistent secrets, encryption keys, and password hashes never appear in API responses.*

---

## 7. Full Repository Backend Test Totals

**Command:**
```powershell
$env:PYTHONPATH="apps/api;apps/demo-target;packages/telemetry-sdk/python"; python -m pytest -v
```

**Complete Test Execution Results:** **306 passed, 0 failed, 1 warning in 80.84s (100% Pass Rate)**

```
=========================== Test Suite Inventory ===========================
- Phase 5 E2E Defensive Loop Scenarios          : 6 passed
- Phase 9 Full System Integration Scenarios     : 8 passed
- Stage 2 Reproduction Tests                   : 13 passed
- Stage 3 Persistence Hardening Tests          : 17 passed
- Stage 4 Comprehensive Regression Suite       : 10 passed
- Stage 5 Acceptance & Certification Suite     : 6 passed
- Independent Security Audit Suite             : 29 passed
- Core Platform & Pipeline Integration Suite   : 197 passed
- Pre-Demo Security Hardening Suite            : 14 passed
- Pre-Demo Secret Lifecycle Verification Suite : 6 passed
----------------------------------------------------------------------------
TOTAL PASSING BACKEND TESTS                    : 306 passed (100%)
TOTAL FAILED TESTS                             : 0
TOTAL SKIPPED TESTS                            : 0
============================================================================
```

---

## 8. Remaining Operational Risks & Disaster Recovery Statement

1. **Loss of Credential Encryption Key:** If the persistent `.env.production` file is deleted or lost without backup, existing encrypted tokens in `cloud_connections` become permanently unrecoverable. The database must be backed up alongside the encryption key.
2. **Single-Worker Execution:** WebSocket tickets and live state broadcasting require a single-worker Uvicorn process (`--workers 1`).
3. **Loopback Default:** Direct exposure to untrusted networks remains prohibited; external network connections require TLS termination via an upstream trusted reverse proxy.

---

## 9. Final Certification Verdict

**VERDICT: RESTART-SAFE PRODUCTION READY**  
The GASHA platform backend is certified for competition demonstration. Persistent secrets are decoupled from one-time bootstrapping credentials, stable across restarts, validated fail-closed against insecure defaults, and verified through 306 automated regression tests. Zero commits or pushes have occurred.

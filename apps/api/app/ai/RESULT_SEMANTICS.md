# GASHA AI / Security Intelligence — Result Semantics Guide

This document establishes the authoritative semantic definitions and epistemic standards for all data models, validations, and outputs produced by the GASHA AI subsystem.

---

## 1. Evidence
An **Evidence Item** is an authoritative, verified unit of forensic data provided to the AI within an `InvestigationContext`.

### Supported Evidence Types:
- `TELEMETRY_EVENT`: Raw probe records (e.g., authentication attempts, HTTP requests, audit logs, process spawns).
- `DETECTION_MATCH`: Deterministic security rule matches emitted by GASHA's detection engine (e.g., brute-force alert, WAF rule trigger).
- `NETWORK_LOG`: NetFlow/VPC traffic records, connection metadata, and port scans.
- `GRAPH_RELATIONSHIP`: Attack-path graph traversal edges connecting assets and credentials.
- `CONFIG_DIFF`: Infrastructure modifications, firewall rule changes, or IAM policy alterations.
- `VULNERABILITY_FINDING`: CVE disclosures and vulnerability assessment findings on affected assets.

> **Invariant:** The AI must **never** invent or hallucinate an evidence identifier. Every cited evidence ID must resolve directly to an item present in the input bundle.

---

## 2. Observed Fact
An **Observed Fact** is a statement directly proven by one or more cited evidence items without subjective interpretation or extrapolation.

### Criteria:
- Must cite at least one valid evidence ID (`evidenceIds: ["<id1>", ...]`).
- Must strictly describe what was recorded (e.g., *"15 failed login attempts for user admin from IP 198.51.100.42"*).
- Must **not** include speculative inferences, unproven threat actor attributions, or breach assumptions.

---

## 3. Inference
An **Inference** is a logical deduction or hypothesis synthesized from observed facts.

### Criteria:
- Must have an explicit `rationale` explaining why the deduction follows from the facts.
- Must cite supporting evidence IDs (`supportingEvidenceIds: [...]`).
- Must carry an explicit `confidence` score between 0.0 and 1.0.
- Must **not** be presented as an immutable fact.

---

## 4. Unknown
An **Unknown** represents an explicit visibility gap, unobserved attack stage, or missing telemetry source.

### Criteria:
- Documents critical missing information required for root-cause confirmation (e.g., *"Initial delivery mechanism is unknown due to missing email gateway logs"*).
- Suggests `recommendedTelemetry` sources to close visibility gaps.

---

## 5. Attempted vs. Successful vs. Confirmed Compromise

| Semantic Category | Definition | Telemetry Indicators | Attack Stage Flag |
| :--- | :--- | :--- | :--- |
| **Attempted (`ATTEMPT_ONLY`)** | Hostile activity was initiated but rejected, blocked, or failed to achieve state change. | `HTTP 401`, `HTTP 403`, `HTTP 400`, WAF rule block, invalid password, connection reset. | `isAttemptOnly: true` |
| **Successful Action** | An individual action completed with state alteration. | Valid authentication (`200 OK`), session token creation, query execution. | `isAttemptOnly: false` |
| **Confirmed Compromise (`CONFIRMED`)** | Unauthorized entity successfully altered security state, escalated privileges, or accessed confidential data. | Privilege escalation to `SUPER_ADMIN`, unauthorized database export, persistence installation. | `compromiseAssessment = "CONFIRMED"` |
| **Not Established (`NOT_ESTABLISHED`)** | Suspicious probing occurred without proof of breach or compromise. | Port scanning, directory traversal probes resulting in 400/403, high-volume failed auth. | `compromiseAssessment = "NOT_ESTABLISHED"` |

> **Invariant:** Negative/blocked activity (e.g., WAF blocked probes, 401/403 errors) must **never** be classified as a confirmed compromise.

---

## 6. Attribution Calibration
- **`ESTABLISHED`**: The threat actor is identified via verified threat intelligence feeds, digital signatures, or infrastructure attribution present in context evidence.
- **`CONSISTENT_WITH_THREAT`**: Observed patterns align with known threat actor TTPs, but identity is unconfirmed (e.g., *"Activity from IP 198.51.100.42 is consistent with automated credential stuffing"*).
- **`UNCONFIRMED`**: No verified external attribution data is available.

> **Rule:** Do **not** use definitive attribution language (*"The attacker did X"*) unless verified attribution evidence is provided. Prefer calibrated wording (*"The activity from source IP X..."*).

---

## 7. Response Recommendations
Defensive recommendations are allowlist-constrained action proposals:

### Allowlist Actions:
1. `BLOCK_SOURCE` (target: `IP_ADDRESS`): Sever network traffic from a malicious external source. Target IP **must** exist in context telemetry/evidence.
2. `DISABLE_SESSION` (target: `USER_SESSION` / `SESSION_ID`): Revoke compromised credentials. Target session **must** exist in context.
3. `ISOLATE_RESOURCE` (target: `ASSET_ID`): Quarantine compromised host. Target asset **must** exist in context asset inventory.

### Non-Negotiable Governance Constraints:
- **Advisory Only:** Recommendations are queued for human analyst approval (`requireManualApproval = True`, `requestedBy = "ANALYST_MANUAL"`).
- **Non-Executable:** Never contains raw shell commands, SQL statements, or arbitrary script code.

---

## 8. Deterministic Fallback
When local LLM inference is offline, times out, or produces ungrounded output:
- Emits structured `AIInvestigationResult` with `status: UNAVAILABLE` or `status: FALLBACK`.
- Baseline facts are deterministically derived from verified detection rules in the context.
- Guarantees zero downtime for backend API consumers while preventing hallucinated claims.

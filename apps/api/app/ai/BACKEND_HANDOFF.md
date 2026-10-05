# GASHA — AI–Backend Integration Handoff Manual

> **Module**: `apps/api/app/ai/`  
> **Target Audience**: Backend Engineers, Incident Pipeline Developers, Security Operations  
> **Supported Context Version**: `1.0.0` (`SUPPORTED_CONTEXT_VERSIONS = {"1.0.0", "1.0", "1.0-mvp"}`)  
> **Status**: Production Integration Ready  

---

## 1. Single Production Entry Point

The GASHA AI subsystem exposes one clean, decoupled service boundary. The Backend caller does not need to know which local LLM is configured, how Ollama API calls are dispatched, how prompts are isolated with XML boundaries, or how grounding validators operate.

### Canonical Callable Signatures

```python
from app.ai.integration import (
    investigate_incident,       # Synchronous -> AIInvestigationResult
    ainvestigate_incident,      # Asynchronous -> AIInvestigationResult
    run_ai_investigation,       # Asynchronous -> AIInvestigationEnvelope (Includes AttackStory & Recs)
    run_ai_investigation_sync,  # Synchronous  -> AIInvestigationEnvelope
    map_to_backend_investigation_response,
    format_recommendation_for_backend,
    is_context_stale
)
```

```python
# Standard Async Investigation
result: AIInvestigationResult = await ainvestigate_incident(context)

# Full Envelope Investigation (with Attack Story & Advisory Recommendations)
envelope: AIInvestigationEnvelope = await run_ai_investigation(context)
```

---

## 2. Input Contract: What Backend Provides

The backend must supply a valid, closed-world `InvestigationContext` (`app.ai.contracts:InvestigationContext`) with `contextVersion = "1.0.0"`:

```json
{
  "contextVersion": "1.0.0",
  "incident": {
    "id": "INC-2026-0042",
    "title": "Brute Force Authentication & Database Exfiltration",
    "severity": "CRITICAL",
    "status": "INVESTIGATING",
    "primaryAffectedAssetId": "srv-auth-cluster",
    "relatedAssetIds": ["srv-api-gateway", "db-customer-pci"],
    "detectionEventIds": ["DET-001", "DET-002"],
    "attackPathId": "PATH-CRIT-01",
    "createdAt": "2026-09-24T02:00:00Z",
    "updatedAt": "2026-09-24T02:05:00Z",
    "summary": "Rapid failed logins followed by sensitive table dump."
  },
  "evidence": [
    {
      "id": "EV-001",
      "type": "TELEMETRY_EVENT",
      "source": "probe.auth_service",
      "timestamp": "2026-09-24T02:01:00Z",
      "summary": "25 failed logins for admin from 198.51.100.42",
      "content": {"ip": "198.51.100.42", "user": "admin", "attempts": 25},
      "verified": true
    }
  ],
  "detections": [
    {
      "id": "DET-001",
      "ruleId": "RULE-AUTH-001",
      "ruleName": "High Frequency Authentication Failure",
      "description": "Brute force authentication pattern",
      "severity": "HIGH",
      "confidence": 0.95,
      "matchedEventIds": ["EV-001"],
      "primaryAssetId": "srv-auth-cluster",
      "timestamp": "2026-09-24T02:02:00Z",
      "evidenceSummary": "Failed logins from single remote IP"
    }
  ],
  "assets": [
    {
      "id": "srv-auth-cluster",
      "name": "Auth Gateway Cluster",
      "type": "AUTHENTICATION_SERVER",
      "criticality": "TIER_1_CRITICAL",
      "isPubliclyExposed": true
    }
  ],
  "attackPath": null,
  "vulnerabilities": [],
  "riskSnapshot": null
}
```

---

## 3. Output Contract: What Backend Receives

The backend receives a stable, validated `AIInvestigationResult` (or `AIInvestigationEnvelope`):

```json
{
  "investigationId": "inv-8f4b1a2c9d01",
  "incidentId": "INC-2026-0042",
  "contextFingerprint": "9a7f3e1b8c0d2e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f",
  "model": "qwen2.5-coder:7b",
  "status": "COMPLETED",
  "isFallback": false,
  "result": {
    "incidentId": "INC-2026-0042",
    "status": "SUCCESS",
    "summary": "Attacker brute-forced admin credentials from 198.51.100.42 and extracted customer DB records.",
    "severity": "CRITICAL",
    "confidence": {
      "score": 0.95,
      "rationale": "High confidence supported by complete forensic auth and query evidence.",
      "evidenceCompleteness": "HIGH",
      "limitations": []
    },
    "observedFacts": [
      {
        "statement": "25 failed login attempts for admin from IP 198.51.100.42.",
        "evidenceIds": ["EV-001"]
      }
    ],
    "inferences": [
      {
        "statement": "Admin credentials were compromised via brute force.",
        "rationale": "Direct sequence of failed attempts followed by authenticated dump.",
        "supportingEvidenceIds": ["EV-001"],
        "confidence": 0.95
      }
    ],
    "unknowns": [
      {
        "statement": "Whether secondary persistent backdoors were installed.",
        "significance": "Complete incident eradication.",
        "recommendedTelemetry": "User audit logs"
      }
    ],
    "attackProgression": [
      {
        "stepOrder": 1,
        "phase": "Initial Access",
        "timestamp": "2026-09-24T02:01:00Z",
        "sourceEntity": "198.51.100.42",
        "targetAssetId": "srv-auth-cluster",
        "description": "Brute force authentication against admin.",
        "isAttemptOnly": false,
        "evidenceIds": ["EV-001"]
      }
    ],
    "affectedAssetIds": ["srv-auth-cluster"],
    "citedEvidenceIds": ["EV-001", "DET-001"],
    "recommendedActions": [
      {
        "id": "rec-1",
        "actionType": "BLOCK_SOURCE",
        "targetIdentifier": "198.51.100.42",
        "targetType": "IP_ADDRESS",
        "rationale": "Source of hostile brute force traffic.",
        "confidence": 0.98,
        "expectedImpact": "Immediately halts active attacker connections.",
        "supportingEvidenceIds": ["EV-001"],
        "priority": "IMMEDIATE"
      }
    ]
  },
  "attackStory": { ... },
  "recommendations": [ ... ]
}
```

---

## 4. Strict Security Boundary & Non-Authoritative Guarantees

> [!IMPORTANT]
> The AI module is strictly **advisory** and **non-authoritative**.
>
> 1. **AI output is untrusted data**: Backend validation remains authoritative.
> 2. **AI never executes response actions**: All recommendations require explicit human approval (`requestedBy='ANALYST_MANUAL'`).
> 3. **AI never changes Digital Twin state**: Graph nodes and relationships cannot be mutated by the AI.
> 4. **AI never modifies risk scores**: Risk recalculations are owned by `app.risk` / `app.adaptive`.
> 5. **AI never modifies attack paths**: Graph traversals are owned by `app.attack_paths`.
> 6. **AI never modifies telemetry or creates evidence**: Telemetry is owned by deterministic probes and ingesters.
> 7. **AI cannot trust instructions inside evidence**: Prompt injections in headers or payloads are treated strictly as inert data strings.

---

## 5. Failure Semantics & Error Codes

| Status Code | Description | Backend Action |
| :--- | :--- | :--- |
| `COMPLETED` / `SUCCESS` | Model reasoning completed and passed all closed-world grounding checks. | Display full AI analysis and recommendations to the analyst. |
| `INSUFFICIENT_EVIDENCE` | Sparse/empty context; confidence $\le 0.3$. | Display uncertainty warning; retain deterministic incident data without AI speculation. |
| `FALLBACK` | Model produced invalid JSON, hallucinated citations, or illegal actions. | Display rule-based deterministic summary labeled as fallback analysis. |
| `UNAVAILABLE` | Local LLM / Ollama connection refused or offline. | Display provider offline banner; do NOT fail the incident pipeline. |
| `TIMEOUT` | Model inference exceeded time budget (30s). | Display timeout fallback; flag for operator inspection. |
| `INVALID_OUTPUT` | JSON syntax parsing failure. | Automatically routed to safe deterministic fallback. |

---

## 6. Backend Integration Checklist

- [ ] Backend constructs `InvestigationContext` from database records.
- [ ] Backend includes `contextVersion = "1.0.0"`.
- [ ] Backend calls `ainvestigate_incident(context)` or `run_ai_investigation(context)`.
- [ ] Backend stores `AIInvestigationEnvelope` in incident cache / database.
- [ ] Backend routes `recommendations` to the Analyst Triage Drawer (`requestedBy='ANALYST_MANUAL'`).
- [ ] Backend invokes `POST /api/v1/responses/execute` ONLY upon explicit human click.
- [ ] Backend recalculates risk and attack paths using deterministic engines following containment.

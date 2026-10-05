# GASHA — Investigation Prompt Specification

## System Prompt Architecture

The investigation system prompt establishes the AI persona, epistemic boundaries, closed-world evidence grounding mandate, response action constraints, and output JSON schema.

```
┌────────────────────────────────────────────────────────┐
│                   System Prompt                        │
│                                                        │
│  1. Persona & Investigation Objective                  │
│  2. Untrusted Data Boundary Definition                 │
│  3. Closed-World Evidence Grounding Mandate            │
│  4. Epistemic Classification Rules                     │
│  5. Response Action Allowlist Constraints              │
│  6. AIInvestigationResult JSON Schema                  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                   User Prompt                          │
│                                                        │
│  <untrusted_security_context>                          │
│  { JSON Serialized InvestigationContext }              │
│  </untrusted_security_context>                         │
└────────────────────────────────────────────────────────┘
```

## Prompt Injection Defense
All security logs, HTTP headers, and user-controlled strings are framed within `<untrusted_security_context>...</untrusted_security_context>`. The system instructions declare that all text within those boundaries is purely forensic data to analyze, never instructions to follow.

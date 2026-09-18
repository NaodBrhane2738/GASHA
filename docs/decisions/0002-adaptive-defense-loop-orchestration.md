# ADR 0002: Adaptive-Defense Loop Orchestration & Execution Safety

## Status
**Accepted**

## Context
A key differentiator of GASHA is the closed-loop Adaptive Defense mechanism: detecting an attack, generating an AI-assisted investigation, executing a response action, mutating environment state, and instantly recalculating risk and attack paths.

## Decision
1. **Deterministic Foundations**: Detection rules and risk scoring are strictly deterministic. Detections do NOT depend on LLMs.
2. **Strictly Allowlisted Responses**: Response execution is limited to three validated actions: `BLOCK_SOURCE`, `DISABLE_SESSION`, and `ISOLATE_RESOURCE`. Arbitrary shell commands are explicitly disallowed.
3. **Evidence Grounding**: AI reasoning operates exclusively on verified `InvestigationContext` objects. If evidence is lacking, the AI outputs *"Insufficient evidence"*.
4. **Adaptive Recalculation**: Every successful response execution triggers an automated mutation of the `EnvironmentState` and recalculation of the Digital Twin, risk score, and active attack paths.

## Consequences
- **Positive**: Prevents destructive execution, eliminates hallucination-driven false actions, guarantees repeatable demo results.

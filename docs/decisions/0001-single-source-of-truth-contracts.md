# ADR 0001: Single Source of Truth for Contracts via `@gasha/contracts`

## Status
**Accepted**

## Context
GASHA is developed concurrently by multiple engineering teams (Backend, Frontend, Cybersecurity, AI, DevOps) alongside a standalone demo target application. In multi-team monorepos, teams often define ad-hoc interfaces for core entities (`Asset`, `TelemetryEvent`, `Incident`, `RiskScore`), causing schema drift and integration friction.

## Decision
All shared data structures, entity models, telemetry schemas, API request/response envelopes, and response action types must be defined exclusively within `packages/contracts` (`@gasha/contracts`) and mirrored directly in `apps/api/app/schemas/`. 

## Consequences
- **Positive**: Eliminates schema drift, guarantees compile-time type safety across frontend and backend, simplifies CI validation.
- **Negative**: Modifying a shared contract requires cross-team consensus.

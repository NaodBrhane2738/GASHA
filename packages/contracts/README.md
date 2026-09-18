# Shared Contracts (`@gasha/contracts`)

> **ROLE / OWNERSHIP**: Shared Platform Architecture (Cross-Team: Backend, Frontend, AI, Cybersecurity, DevOps)  
> **OBJECTIVE**: Provide the single source of truth for all domain entities, event schemas, API envelopes, and allowlisted response actions.  
> **TOOLS & LIBRARIES**: TypeScript 5.x, JSON Schema / Zod definitions  
> **EXPECTED RESULT**: Complete type safety across frontend and backend; zero redundant model declarations.

---

## Structure
- [`entities/index.ts`](file:///d:/CODING/GASHA/packages/contracts/entities/index.ts): Domain models (`Asset`, `Relationship`, `Vulnerability`, `RiskScore`, `AttackPath`, `Incident`, `Evidence`, `InvestigationContext`, `EnvironmentState`).
- [`events/index.ts`](file:///d:/CODING/GASHA/packages/contracts/events/index.ts): Runtime schemas (`TelemetryEvent`, `DetectionEvent`, `SystemEvent`).
- [`api/index.ts`](file:///d:/CODING/GASHA/packages/contracts/api/index.ts): Standard envelopes (`ApiResponse`, `ApiError`, `PaginatedResult`).
- [`responses/index.ts`](file:///d:/CODING/GASHA/packages/contracts/responses/index.ts): Allowlisted actions (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`).
- [`index.ts`](file:///d:/CODING/GASHA/packages/contracts/index.ts): Root barrel export.

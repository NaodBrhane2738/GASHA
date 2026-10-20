# Agent & AI Integration Guide: GASHA Architecture & Parity Handbook

> **Audience**: AI Agents, Autonomous Coding Assistants (Antigravity, Claude, Cursor, Copilot), and DevOps/Cybersecurity Engineers working on the GASHA platform.  
> **Objective**: Prevent recurring integration mismatches, maintain contract parity across TypeScript and Python, enforce security invariants (Four-Eyes Principle, evidence grounding), and provide deterministic troubleshooting instructions.

---

## 1. System Architecture & Monorepo Structure

```
GASHA/
├── apps/
│   ├── api/                   # FastAPI backend (Python 3.13)
│   │   ├── app/
│   │   │   ├── api/           # Endpoints: auth, digital-twin, attack-paths, detections, incidents, responses, realtime
│   │   │   ├── core/          # Security, auth guards, config, JWT creation & verification
│   │   │   ├── db/            # Thread-safe in-memory repositories + Postgres / Supabase engines
│   │   │   └── schemas/       # Pydantic v2 schemas strictly mirroring @gasha/contracts
│   │   └── tests/             # 160+ unit tests + integration suites
│   └── web/                   # Next.js 16 (App Router + Turbopack + React 19)
│       ├── src/
│       │   ├── app/           # Routes: /, /twin, /detections, /incidents, /paths, /risk, /response, /telemetry
│       │   ├── components/    # Cytoscape/xyflow Digital Twin, timelines, risk sparklines, modal dialogs
│       │   ├── lib/api/       # API client with automatic JWT bearer auth & query hooks
│       │   ├── lib/realtime/  # Live WebSocket client (useEventStream)
│       │   └── types/         # Domain TypeScript models
├── packages/
│   ├── contracts/             # Shared TypeScript models (@gasha/contracts)
│   │   ├── entities/          # Asset, Relationship, AttackPath, Incident, RiskScore, Evidence
│   │   ├── events/            # TelemetryEvent, DetectionEvent, SystemEvent, RealtimeMessage
│   │   ├── responses/         # ResponseActionRequest, ResponseAuditRecord
│   │   └── api/               # ApiResponse, Pagination, WebSocketTicketRequest/Response
│   └── telemetry-sdk/         # Runtime telemetry collector for Python & Node.js
├── test_full_stack.py         # 65-test complete full-stack integration verification runner
└── test_e2e_integration.py    # 20-step end-to-end integration test runner
```

---

## 2. Shared Contracts & Type Parity Invariants

All entity and event schemas **MUST** remain identical across `packages/contracts`, `apps/api/app/schemas/`, and `apps/web/src/types/domain.ts`.

### 2.1 Attack Paths (`AttackPath`)
- **Required Fields**:
  - `id: string`
  - `entryPointAssetId: string` (and alias `entryNodeId: string`)
  - `targetAssetId: string` (and alias `crownJewelNodeId: string`)
  - `severity: SeverityLevel` ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')
  - `pathScore: number` (and alias `riskScore: number`, 0-100)
  - `nodes: AttackPathNode[]`
  - `techniques: string[]` **(CRITICAL)**: Array of MITRE ATT&CK technique IDs (e.g. `['T1190', 'T1078', 'T1552']`). The frontend page `/paths` requires this array; never omit it.
  - `likelihood: number` (0.0 - 1.0)
  - `impact: number` (0.0 - 1.0)
  - `status: 'open' | 'mitigated' | 'accepted'`
- **Frontend Rule**: Always guard with `(p.techniques ?? []).map(...)` and `(p.nodeIds ?? []).length`.

### 2.2 Detections (`DetectionEvent` / `Detection`)
- **Rule Property**: The backend sends `rule` as a structured object:
  ```json
  {
    "ruleId": "RULE-AUTH-001",
    "name": "Brute-force authentication attempt",
    "description": "5 failed logins in 12s",
    "severity": "HIGH",
    "confidence": 0.92
  }
  ```
- **React Rendering Rule**: Never render `{d.rule}` directly in JSX, as React will throw an unhandled object error (`Objects are not valid as a React child`). Extract the text:
  ```tsx
  const ruleName = typeof d.rule === 'object' && d.rule !== null
    ? (d.rule.name || d.rule.ruleId)
    : String(d.rule ?? '');
  ```
- **Contract Parity Fields**: The backend `DetectionEventResponse` auto-populates `ts`, `nodeId`, `technique`, and `summary` via Pydantic `model_post_init` so frontend consumers get both high-level and detailed structures.

### 2.3 Incidents (`Incident`)
- **Parity Fields**: The backend `IncidentResponse` auto-populates `openedAt` (from `createdAt`), `detectionIds` (from `detectionEventIds`), `pathId` (from `attackPathId`), `confidence` (0.90), and `riskBefore` (75.0) via `model_post_init`.
- **Status Machine**: Valid transitions are strictly enforced:
  - `ACTIVE` &rarr; `INVESTIGATING` | `CONTAINED` | `RESOLVED`
  - `INVESTIGATING` &rarr; `CONTAINED` | `RESOLVED` | `ACTIVE`
  - `CONTAINED` &rarr; `RESOLVED` | `INVESTIGATING`
  - `RESOLVED` &rarr; `ACTIVE` | `INVESTIGATING`

### 2.4 Controlled Responses (`ResponseRecordResponse` / `ResponseAction`)
- **Parity Fields**:
  - `kind`: maps `BLOCK_SOURCE` &rarr; `"block-ip"`, `DISABLE_SESSION` &rarr; `"revoke-session"`, `ISOLATE_RESOURCE` &rarr; `"isolate-host"`
  - `target`: from `targetIdentifier`
  - `state`: maps `PROPOSED`/`PENDING_APPROVAL` &rarr; `"proposed"`, `APPROVED` &rarr; `"approved"`, `SUCCEEDED`/`COMPLETED` &rarr; `"done"`, `FAILED` &rarr; `"failed"`, `REJECTED` &rarr; `"rejected"`
  - `blastRadius`: `{ nodeIds: [targetIdentifier], servicesAffected: [...] }`
  - `riskReduction`: projected points (15)

### 2.5 Risk Engine (`RiskScoreResponse` / `RiskHistoryEntryResponse`)
- **History Parity**: `RiskHistoryEntryResponse` populates `ts` (from `timestamp`), `openPaths` (from `activeAttackPathsCount`), and `openIncidents` (from `activeIncidentsCount`) via `model_post_init`.
- **UI Charting**: Safe navigation `payload?.[0]?.payload?.ts` and `score` mapping.

---

## 3. Realtime Live Feed & WebSockets

### 3.1 Architecture
The platform streams live threat events and platform mutations over partitioned WebSockets, **NOT** polling.
- **WebSocket Route**: `ws://<HOST>:<PORT>/api/v1/realtime/ws?ticket=<TICKET>`
  - Route aliases: `/api/v1/ws`, `/ws`
- **Ticket Route**: `POST /api/v1/realtime/ticket` (requires Bearer auth)
  - Route aliases: `/api/v1/ticket`, `/ticket`
  - Issues single-use high-entropy tickets with a 60-second TTL bound to the user's `environmentId`.
- **JWT Fallback**: In direct agent connections, `?token=<JWT>` is also accepted.
- **Keep-Alives**: Ping message strings or `{"type": "ping"}` receive immediate `"pong"` responses.

### 3.2 Frontend Hook (`useEventStream`)
- Located in `apps/web/src/lib/realtime/useEventStream.ts`.
- Automatically fetches a ticket, connects via WebSocket, deserializes JSON broadcasts, maps them to `Detection`, and handles exponential backoff reconnects.

---

## 4. Cybersecurity Invariants & State Machines

### 4.1 Four-Eyes Principle / Separation of Duties (CRITICAL)
- **Rule**: An operator who proposes a containment action **CANNOT** approve or reject their own proposal.
- **Enforcement**: `ResponseService.review_proposal()` will reject the approval with `HTTP 400 Bad Request` if the actor matches `proposedBy`.
- **Testing Pattern**:
  1. `operator` (`OperatorSecure2026!`) proposes containment action.
  2. `admin` (`AdminRoot2026!`) approves or rejects the proposal.

### 4.2 Evidence Grounding for Containment
- Containment actions (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`) **must be grounded in verified incident evidence**.
- Proposing containment for a target IP/User not present in the incident's detection metadata will be rejected with `HTTP 400 Bad Request`.
- In standard test seeds for `inc-1`, the attacker IP is `198.51.100.42`.

### 4.3 Deterministic Seeding vs. Pytest Isolation
- Repositories (`asset_repository.py`, `incident_repository.py`, etc.) seed baseline demonstration data.
- **MANDATORY**: Seeding is guarded by:
  ```python
  if is_production_mode() or "PYTEST_CURRENT_TEST" in os.environ:
      return
  ```
- **Do NOT remove this guard**. Pytest tests rely on empty isolated repositories for unit testing.

---

## 5. Third-Party Licenses & Compliance

### 5.1 xyflow / React Flow Attribution
- **Rule**: The React Flow attribution badge (`.react-flow__attribution`) MUST remain visible unless an enterprise Pro subscription is configured.
- **Violations to avoid**:
  - Do NOT set `proOptions={{ hideAttribution: true }}` on `<ReactFlow />`.
  - Do NOT add `.react-flow__attribution { display: none; }` to `globals.css`.

---

## 6. Verification & Test Commands

Before committing any modifications, run the following verification suite:

```powershell
# 1. Typecheck Shared Contracts
node d:\CODING\GASHA-abdu\node_modules\typescript\bin\tsc -p packages/contracts/tsconfig.json --noEmit

# 2. Run Backend Unit & Integration Tests (160+ tests)
$env:PYTHONPATH="apps/api;packages/telemetry-sdk/python"
pytest apps/api/tests

# 3. Run Telemetry SDK Tests (22 tests)
$env:PYTHONPATH="packages/telemetry-sdk/python"
pytest packages/telemetry-sdk/python/tests

# 4. Verify Frontend Production Build (Turbopack)
npm --prefix d:\CODING\GASHA-abdu run build

# 5. Run Full-Stack 65-Endpoint Test Suite
python -u test_full_stack.py

# 6. Run Full End-to-End Stack Verification
python test_e2e_integration.py
```

---

## 7. Standard Seed Credentials (`env-prod`)

| Username | Password | Role | Environment | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| `operator` | `OperatorSecure2026!` | `security_operator` | `env-prod` | Propose & review containment, read all telemetry |
| `admin` | `AdminRoot2026!` | `admin` | `env-prod` | Full admin privileges, dual-approval gate |
| `analyst` | `AnalystSecure2026!` | `security_analyst` | `env-prod` | Read-only investigations & incident queries |
| `breakglass` | `EmergencyRoot2026!` | `emergency_admin` | `env-prod` | Emergency override & lockdown operations |

Telemetry Ingestion Header:
```
X-GASHA-TELEMETRY-KEY: gasha-telemetry-demo-key-2026
```

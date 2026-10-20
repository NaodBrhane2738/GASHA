# GASHA — Graph-Adaptive Security & Hardening Architecture

> **Adaptive Autonomous Defense Platform for Cloud-Native & Serverless Environments**
> *Built as a high-velocity Turborepo monorepo for seamless cross-team engineering.*
> **AI & Agent Handbook**: See [docs/AGENT_INTEGRATION_GUIDE.md](docs/AGENT_INTEGRATION_GUIDE.md) for cross-contract parity, Four-Eyes Principle approval rules, WebSocket streaming, and integration troubleshooting.

---

## 1. Overview & Mission

GASHA is an automated, graph-driven security platform designed to discover, visualize, assess, detect, investigate, and autonomously mitigate cyber threats in modern web applications and cloud infrastructure.

Traditional security tools operate in disconnected silos: vulnerability scanners lack runtime context, SIEMs ingest logs without topology awareness, and SOAR playbooks are brittle. **GASHA unifies static infrastructure graph analysis with real-time runtime telemetry into a continuous, self-healing Adaptive-Defense Loop.**

```
AUTHORIZED ENVIRONMENT (Vercel & GitHub)
   │
   ▼
1. DISCOVERY & INGESTION ──► 2. DIGITAL TWIN (Security Graph)
                                      │
                                      ▼
                             3. SECURITY ASSESSMENT (Exposure Engine)
                                      │
                                      ▼
                             4. RISK CALCULATION ENGINE
                                      │
                                      ▼
                             5. ATTACK-PATH CALCULATION ENGINE
                                      │
DEMO APPLICATION ──► 6. RUNTIME TELEMETRY ──┘
                           │
                           ▼
                     7. DETERMINISTIC DETECTION ENGINE
                           │
                           ▼
                     8. INCIDENT CORRELATION ENGINE
                           │
                           ▼
                    9. INVESTIGATION CONTEXT AGGREGATOR
                           │
                           ▼
                   10. AI REASONING (Grounded Storytelling & Recommendations)
                           │
                           ▼
                   11. CONTROLLED RESPONSE EXECUTION (Allowlisted Actions)
                           │
                           ▼
                   12. ENVIRONMENT STATE MUTATION & INSTANT RECALCULATION
                           │
                           ▼
                   [RETURN TO DIGITAL TWIN / ADAPTIVE STATE]
```

---

## 2. Monorepo Structure & Team Ownership

This repository is organized as a standard **Turborepo / pnpm workspace** uniting deployable applications (`apps/`), shared typed contracts (`packages/`), and architecture specifications (`docs/`):

```
gasha/
├── apps/
│   ├── api/                  # [Backend & AI Teams] FastAPI backend & security reasoning engine
│   │   ├── app/
│   │   │   ├── adaptive/     # Adaptive defense orchestrator & state manager
│   │   │   ├── ai/           # AI reasoning, evidence grounding, prompts & model adapters
│   │   │   ├── api/          # FastAPI REST endpoints & WebSocket channels
│   │   │   ├── core/         # Config, auth, errors, logging, security utils
│   │   │   ├── db/           # Database models, connection pool, repositories
│   │   │   ├── detection/    # Deterministic sequence & threshold detection engine
│   │   │   ├── digital_twin/ # Security graph builder, traversal queries & state
│   │   │   ├── discovery/    # Vercel & GitHub ingestion, normalizer & deduplicator
│   │   │   ├── response/     # Controlled, allowlisted response execution
│   │   │   ├── risk/         # Quantitative risk calculation engine
│   │   │   ├── schemas/      # Pydantic request/response validation schemas
│   │   │   ├── telemetry/    # High-throughput telemetry ingestion pipeline
│   │   │   └── workers/      # Asynchronous discovery & recalculation background jobs
│   │   └── tests/            # Backend unit, integration, and e2e test suites
│   ├── web/                  # [Frontend Team] Next.js Dashboard, Digital Twin & Incident Views
│   └── demo-target/          # [Defended App] Reference web application monitored by GASHA SDK
│
├── packages/
│   ├── contracts/            # [Single Source of Truth] Shared TypeScript/Pydantic schemas
│   ├── detection-rules/      # [Cybersecurity Team] Security detection rule signatures & specs
│   ├── telemetry-sdk/        # Reusable client SDK (TypeScript & Python)
│   └── ui/                   # Shared UI primitives, icons, and theme tokens
│
├── docs/                     # [Architecture & Threat Models]
│   ├── architecture/         # System architecture, data flow, adaptive loop
│   ├── competition/          # MVP scope, demo script, judging criteria
│   ├── cybersecurity/        # Attack scenarios, threat research, response constraints
│   ├── ai/                   # Grounding methodology, benchmark tests, prompts
│   ├── decisions/            # Architecture Decision Records (ADR-0001, ADR-0002)
│   └── integrations/         # Vercel & GitHub OAuth setup and webhook specifications
│
├── infra/                    # Docker Compose, PostgreSQL init, deployment manifests
├── scripts/                  # Developer automation (dev, setup, seed, demo, reset, test)
├── tests/                    # Project-level integration, contract, and scenario test suites
├── .github/                  # GitHub Actions CI workflow, PR & issue templates
├── pnpm-workspace.yaml       # Workspace package definitions
├── turbo.json                # Turborepo task pipeline cache configuration
├── package.json              # Monorepo root scripts
├── .env.example              # Consolidated environment variable configuration template
└── CONTRIBUTING.md           # Collaboration conventions & branch rules
```

---

## 3. Team Responsibilities & Ownership Matrix

| Area | Primary Owners | Core Deliverables |
| :--- | :--- | :--- |
| **`apps/api`** | **Backend & AI Engineers** | FastAPI API routes, Digital Twin graph engine, deterministic detection rules, risk calculations, attack-path discovery, allowlisted response execution, LLM investigation orchestration, and adaptive loop state transitions. |
| **`apps/web`** | **Frontend Engineers** | Next.js 14+ App Router, interactive graph canvas (React Flow / Cytoscape), real-time WebSocket state subscriptions, incident triage drawer, and response execution UI. |
| **`packages/contracts`** | **All Teams (Cross-Team)** | **Single Source of Truth** for shared data contracts (`Asset`, `Relationship`, `Vulnerability`, `RiskScore`, `AttackPath`, `Incident`, `Evidence`, `TelemetryEvent`, `ResponseActionType`). |
| **`packages/detection-rules`** | **Cybersecurity Researchers** | Deterministic detection rule specifications, attack signatures, threshold values, and time-window correlation rules. |
| **`packages/telemetry-sdk`** | **Shared SDK Owners** | High-performance, non-blocking telemetry emitter library for Node.js / TypeScript and Python services. |
| **`apps/demo-target`** | **Full Team** | Customer reference web app with controlled, intentional demonstration vulnerabilities monitored in real-time by GASHA. |
| **`infra/` & CI/CD** | **DevOps Engineers** | Multi-container Docker topologies, PostgreSQL & Redis setups, Vercel/GitHub integration configuration, and automated CI pipelines. |

---

## 4. Key Architectural Boundaries

1. **GASHA is ONE System**: The backend is a unified modular application inside `apps/api`, not fragmented microservices.
2. **Deterministic Security Decisions**: Detection and risk scoring do **not** rely on LLMs. They are deterministic state machines and graph algorithms.
3. **Evidence-Grounded AI**: The AI reasoning layer operates strictly on structured `Evidence` supplied by the backend. If evidence is lacking, the AI explicitly returns *"Insufficient evidence"*.
4. **Allowlisted Response Actions**: Containment actions are strictly restricted to `BLOCK_SOURCE`, `DISABLE_SESSION`, and `ISOLATE_RESOURCE`. Arbitrary shell execution is forbidden.
5. **Single Source of Truth**: All shared models originate in `packages/contracts` and `apps/api/app/schemas/`.

---

## 5. Local Setup & Development

### Prerequisites
- **Node.js**: `v20.x+` & **pnpm**: `v9.x+` (or `npm`)
- **Python**: `3.13` & `pip`. On Windows create the environment with `py -3.13 -m venv .venv`.
- **Docker**: For PostgreSQL & Redis

### Quickstart
```bash
# 1. Clone repository
git clone https://github.com/NaodBrhane2738/GASHA.git
cd GASHA

# 2. Copy environment template
cp .env.example .env

# 3. Start PostgreSQL and Redis containers
docker compose up -d

# 4. Install JavaScript/TypeScript dependencies
pnpm install

# 5. Set up Python virtual environment for FastAPI backend
cd apps/api
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
pip install -r requirements.txt  # Or poetry install
uvicorn app.main:app --reload --port 4000
```

---

## 6. Branching & Contribution Workflow

See [`CONTRIBUTING.md`](file:///d:/CODING/GASHA/CONTRIBUTING.md) for full guidelines.
- `feature/backend-<topic>` : Backend APIs, graph algorithms & engines
- `feature/frontend-<topic>` : Web dashboard & graph visualizations
- `feature/cyber-<topic>` : Detection rules & attack scenarios
- `feature/ai-<topic>` : Prompts, grounding & model benchmarks
- `feature/devops-<topic>` : Infrastructure, Docker & CI/CD
- `fix/<team>-<topic>` : Bug fixes

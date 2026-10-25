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

## 5. Collaborator 1-Click Quickstart

To run the entire platform with all 4 services concurrently:

### Prerequisites
- **Node.js**: `v20.x+` & **pnpm**: `v9.x+`
- **Python**: `3.10+` & `pip`

### Step-by-Step Setup
```bash
# 1. Clone repository
git clone https://github.com/NaodBrhane2738/GASHA.git
cd GASHA

# 2. Install dependencies
pnpm install
pip install -r apps/api/requirements.txt

# 3. Start all services with one command:
python run_all.py
# Or on Windows, simply double-click start_all.bat
# Or via pnpm: pnpm dev:all
```

### Services & URLs
| Service | URL | Description |
| :--- | :--- | :--- |
| **GASHA Web Console** | `http://localhost:3100` | Security operations dashboard & Digital Twin |
| **Nexus Storefront Target** | `http://localhost:3101` | Live defended demo e-commerce app |
| **Attacker Simulation Console** | `http://localhost:3102` | Interactive red-team attack trigger console |
| **GASHA Core API** | `http://localhost:4000/docs` | FastAPI backend & interactive Swagger docs |

### Default Credentials
- **Username**: `analyst01`
- **Password**: `agis`

---

### Accessing Over Local Network (Wi-Fi)
If a collaborator on the same Wi-Fi network needs to access your running instance at `http://<your-ip>:3100`:
1. **Windows Network Profile**: The host machine's Wi-Fi network category MUST be set to **Private Network** (Windows Defender Firewall blocks incoming connections on Public networks by default):
   - Open **Settings** > **Network & internet** > **Wi-Fi**
   - Click on your connected Wi-Fi network
   - Change Network profile type from **Public** to **Private**
2. **Finding Your IP**: Run `ipconfig` in terminal (look for IPv4 Address under Wireless LAN adapter, e.g. `192.168.1.x`).
3. **Collaborator Access**: The collaborator can now navigate to:
   - Web Console: `http://192.168.1.x:3100`
   - Target Store: `http://192.168.1.x:3101`
   - Attacker Console: `http://192.168.1.x:3102`

---

## 6. Advanced Local Setup & Development

### Prerequisites
- **Node.js**: `v20.x+` & **pnpm**: `v9.x+` (or `npm`)
- **Python**: `3.13` & `pip`. On Windows create the environment with `py -3.13 -m venv .venv`.
- **Docker**: For PostgreSQL & Redis

### Quickstart
```bash
# 1. Clone repository
git clone https://github.com/NaodBrhane2738/GASHA.git
cd GASHA

# 2. Non-destructive setup helper (copies .env.example → .env if missing)
python scripts/setup/setup_local.py

# 3. Edit .env — never commit it. Generate secrets:
python scripts/dev/generate_secrets.py

# 4a. Database services only (host runs API + web):
docker compose up -d postgres redis

# 4b. Or full stack (builds web + api images too):
# docker compose up --build

# 5. Install JavaScript/TypeScript dependencies
pnpm install

# 6. Python environment for the API
py -3.13 -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r apps/api/requirements-dev.txt

# 7. Postgres schema (Supabase Session pooler DATABASE_URL recommended)
#    Local Compose Postgres may fail until the service_role decision is made —
#    see docs/database-provisioning.md
python scripts/dev/migrate.py --status
# python scripts/dev/migrate.py --yes

# 8. Run API on the host (SQLite/memory defaults work without step 7)
cd apps/api
uvicorn app.main:app --reload --port 4000

# Demo launcher (API + dashboard): python scripts/demo/run_demo.py --persist
# Checks: python scripts/test/run_checks.py
```

Deployable API blueprint: [`render.yaml`](render.yaml). Integration notes: [`docs/integrations/`](docs/integrations/).

---

## 7. Branching & Contribution Workflow

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full guidelines.
- `feature/backend-<topic>` : Backend APIs, graph algorithms & engines
- `feature/frontend-<topic>` : Web dashboard & graph visualizations
- `feature/cyber-<topic>` : Detection rules & attack scenarios
- `feature/ai-<topic>` : Prompts, grounding & model benchmarks
- `feature/devops-<topic>` : Infrastructure, Docker & CI/CD
- `fix/<team>-<topic>` : Bug fixes

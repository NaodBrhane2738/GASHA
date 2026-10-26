# GASHA — Graph-Adaptive Security & Hardening Architecture

> **Autonomous Cyber Defense & Digital Twin Platform for Cloud-Native Environments**  
> *Engineered as a high-performance Turborepo monorepo uniting graph topology, runtime telemetry, deterministic detection, and controlled response containment.*  
> **AI & Agent Handbook**: See [`docs/AGENT_INTEGRATION_GUIDE.md`](docs/AGENT_INTEGRATION_GUIDE.md) for cross-contract parity, Four-Eyes Principle approval constraints, cryptographic audit logging, and WebSocket telemetry contracts.

---

## 1. Overview & Mission

Modern enterprise cybersecurity is plagued by fragmented tool silos: static cloud security posture managers lack runtime telemetry, SIEM systems ingest logs without infrastructure topology context, and traditional SOAR playbooks are brittle.

**GASHA unifies static infrastructure graph analysis with real-time runtime telemetry into a continuous, self-healing Adaptive-Defense Loop.**

```
AUTHORIZED CLOUD / HOST ENVIRONMENT (Vercel, GitHub, Cloud Infrastructure)
   │
   ▼
1. DISCOVERY & INGESTION ──► 2. DIGITAL TWIN (Security Graph Topology)
                                       │
                                       ▼
                             3. EXPOSURE & ATTACK PATH ENGINE
                                       │
                                       ▼
                             4. QUANTITATIVE RISK SCORING (0-100)
                                       │
                                       ▼
DEMO APPLICATION (Nexus) ──► 5. RUNTIME TELEMETRY STREAM
                                       │
                                       ▼
                             6. DETERMINISTIC DETECTION ENGINE
                                       │
                                       ▼
                             7. INCIDENT CORRELATION & CVE MAPPING
                                       │
                                       ▼
                             8. INVESTIGATION CONTEXT AGGREGATOR
                                       │
                                       ▼
                             9. CONTROLLED RESPONSE EXECUTION (Allowlisted Actions)
                                       │
                                       ▼
                            10. ENVIRONMENT MUTATION & AUTOMATIC RESTORATION
                                       │
                                       ▼
                       [RETURN TO NOMINAL DIGITAL TWIN & ARCHIVE]
```

---

## 2. Core Capabilities & Architectural Pillars

### 1. Digital Twin & Security Topology (`/twin`)
- **Interactive Security Graph**: Visualizes infrastructure nodes (API Gateways, Auth Services, Data Stores, Public Endpoints) and their interconnections.
- **Attack-Path Tracing**: Real-time rendering of active adversary traversal paths and lateral movement risks.
- **Automatic State Normalization**: When an adversary IP is blocked, affected assets immediately revert to baseline nominal state (`Risk: 15`), displaying `PROTECTED & NOMINAL · CONTAINED` with zero flashing or radar waves.
- **Node Inspector Side Card**: Detailed node criticality, exposure level, live forensic incursion narratives, and one-click perimeter containment actions.

### 2. Active Containment & "Execute Block" Flow (`/response`)
- **Allowlisted Action Boundaries**: Defense actions are strictly governed (`BLOCK_SOURCE`, `ISOLATE_RESOURCE`, `DISABLE_SESSION`). Arbitrary shell execution is strictly prohibited.
- **Immediate Quarantine Execution**: Prominent **`Execute Block & Move to Archive`** actions available directly on the Digital Twin and Containment Center.
- **Targeted Perimeter Drop**: Calls the defended target perimeter firewall (`/api/demo/block-ip`) to drop all malicious packets at the network edge.
- **Four-Eyes Review Option**: Modal preview of blast radius and projected risk score reduction before manual approval confirmation.

### 3. Date-Based Incident Archives (`/database` & `/response?view=archives`)
- **Calendar-Based Folder Organization**: Groups all historical and newly mitigated incidents into date folders (e.g., `Today`, `Yesterday`, `YYYY-MM-DD`).
- **Comprehensive Incident Dossiers**: Each archived case contains full forensic descriptions, CVE mappings, MITRE ATT&CK techniques, risk before/after metrics, and verified containment logs.
- **Automatic Archival**: Once a threat is executed and blocked, it is sealed and transferred directly into the current date's archive folder.

### 4. Operation Side Drawer Navigation & Minimalist Dark UI
- **Quick-Access Drawer**: Click the **Operation** button in the header (or press `ESC`) to slide out navigation across Observe, Triage, Respond, Digital Twin, Paths, Risk, and Database.
- **Centered Enterprise Branding**: Clean header centering **`GASHA AEGIS`**.
- **100% Emoji-Free & Non-Flashy**: Stripped of distracting animations, toy emojis, and pulsating radars in favor of a crisp, military-grade dark cybersecurity console.

### 5. Multi-Vector Attacker Simulator (`apps/attacker-console`)
- Dedicated attacker portal running on `localhost:3102` to trigger live, realistic attack campaigns against the defended application:
  - **Credential Stuffing / Brute Force** (MITRE T1110)
  - **SQL Injection Payload Incursion** (MITRE T1190)
  - **SSRF Cloud Metadata Pivot** (MITRE T1190 / T1552)
  - **Path Traversal & Arbitrary File Access** (MITRE T1083)
  - **Volumetric API Flood / DDoS** (MITRE T1499)

---

## 3. Monorepo Architecture & Directory Structure

```
gasha/
├── apps/
│   ├── api/                  # FastAPI backend & security reasoning engine (Port 4000)
│   │   ├── app/
│   │   │   ├── adaptive/     # Adaptive defense loop state machine
│   │   │   ├── api/          # REST endpoints (/twin, /incidents, /responses, /telemetry)
│   │   │   ├── core/         # Config, crypto hash chaining, security utils
│   │   │   ├── detection/    # Deterministic sequence & sliding-window rule engine
│   │   │   ├── digital_twin/ # Graph models, layout algorithms, path traversal
│   │   │   ├── response/     # Controlled response executor & demo target enforcer
│   │   │   ├── risk/         # Quantitative scoring & risk reduction models
│   │   │   └── schemas/      # Pydantic validation contracts
│   │   └── tests/unit/       # 160+ unit test suite
│   │
│   ├── web/                  # Next.js 16 Web Dashboard & UI Console (Port 3100)
│   │   ├── src/app/          # Next.js App Router pages (twin, response, database, etc.)
│   │   ├── src/components/   # React Flow TwinGraph, IncidentArchiveView, ActionCard
│   │   ├── src/lib/api/      # TanStack Query API hooks & WebSocket clients
│   │   └── src/store/        # Zustand state store with persistent containment ledger
│   │
│   ├── demo-target/          # Live Defended Target Application (Port 3101)
│   │   ├── main.py           # FastAPI reference service with telemetry emitter
│   │   └── blocklist.py      # Runtime perimeter firewall blocklist table
│   │
│   └── attacker-console/     # Interactive Red-Team Threat Simulator (Port 3102)
│       └── main.py           # Web UI to fire automated security incursion scenarios
│
├── packages/
│   ├── contracts/            # Single Source of Truth TypeScript schema contracts
│   ├── detection-rules/      # Deterministic MITRE ATT&CK rule signatures
│   ├── telemetry-sdk/        # Emitter SDK for Node.js and Python runtimes
│   └── ui/                   # Shared UI primitives, badges, and tokens
│
├── docs/                     # Architectural specs, ADRs, and Agent Integration Guide
├── run_all.py                # Single-command launcher for all 4 services
└── start_all.bat             # Windows one-click batch launcher
```

---

## 4. Quick Start (Zero External Servers Required)

GASHA is completely self-contained. **No external database, Docker daemon, or cloud setup** is required to run the full platform.

### Prerequisites
- **Node.js**: `v20.x` or higher (with `pnpm` or `npm`)
- **Python**: `3.10` or higher (with `pip`)

### Step-by-Step Launch

```bash
# 1. Clone repository
git clone https://github.com/NaodBrhane2738/GASHA.git
cd GASHA

# 2. Install JavaScript & Python dependencies
pnpm install
pip install -r apps/api/requirements.txt

# 3. Launch all 4 services simultaneously
python run_all.py
```

*(On Windows, you can also double-click `start_all.bat` or run `pnpm dev:all`)*

---

## 5. Services & Port Map

All four micro-services run locally on `127.0.0.1`:

| Service | Local URL | Description |
| :--- | :--- | :--- |
| **GASHA Web Console** | [`http://localhost:3100`](http://localhost:3100) | Security operations dashboard, Digital Twin & Archives |
| **Nexus Storefront Target** | [`http://localhost:3101`](http://localhost:3101) | Live defended web app with real-time telemetry |
| **Attacker Simulation Console** | [`http://localhost:3102`](http://localhost:3102) | Red-team interactive adversary incursion console |
| **GASHA Core API** | [`http://localhost:4000/docs`](http://localhost:4000/docs) | FastAPI backend & interactive OpenAPI/Swagger docs |

### Default Analyst Credentials
- **Username**: `analyst01`
- **Password**: `agis`

---

## 6. End-to-End Incident & Containment Walkthrough

1. **Trigger Threat Incursion**:
   - Open [`http://localhost:3102`](http://localhost:3102) (Attacker Console).
   - Click **Trigger Brute Force Attack** or **Trigger SSRF Probe**.
2. **Observe Real-Time Detection**:
   - Navigate to [`http://localhost:3100/twin`](http://localhost:3100/twin) (Digital Twin).
   - The targeted node (`auth-svc` or `nexus-target`) highlights the attack technique, risk score jumps to **99**, and the adversary IP is flagged.
3. **Execute Block**:
   - In the node inspector card, click **`Execute Block & Move to Archive`** (or click **`Quarantine & Review in Response`** to open `/response`).
   - The perimeter firewall drops the adversary IP immediately.
4. **Inspect Normalization & Date Archives**:
   - The Digital Twin immediately drops node risk back to nominal **15**, displays `PROTECTED & NOMINAL · CONTAINED`, and displays all systems nominal.
   - The incident is transferred to the **Date Archives** under today's date (`2026-10-26`), complete with CVE details and risk mitigation metrics.

---

## 7. Quality Assurance & Verification

### Run Frontend Static Production Build
```bash
pnpm --filter @gasha/web build
```
*Validates TypeScript types and compiles all 14 application routes with zero errors.*

### Run Backend Unit Test Suite
```bash
# On Windows PowerShell:
$env:PYTHONPATH="apps/api"; pytest apps/api/tests/unit/

# On Linux / macOS:
PYTHONPATH=apps/api pytest apps/api/tests/unit/
```
*Runs all 160 unit tests across detection, graph traversal, risk calculation, crypto audit, and response enforcement.*

---

## 8. Security & Cryptographic Integrity

1. **Deterministic Execution**: Incursion detection and risk evaluation rely on deterministic state engines, eliminating non-deterministic hallucinations in security decisions.
2. **Cryptographic Audit Hash Chain**: Every response proposal, approval, and execution event is committed to a tamper-evident, SHA-256 hash-chained audit ledger accessible via `/responses/audit`.
3. **Four-Eyes Authorization**: High-impact containment actions require operator confirmation with blast-radius analysis before firewall changes are committed.
4. **Zero Shell Execution**: No dynamic command strings or untrusted shell execution are permitted anywhere in the platform.

---

## 9. Project Team & Contributors

This project was engineered and developed by:

| Contributor | Student / Identification ID |
| :--- | :--- |
| **Naod Brhane** | CTC-624-26 |
| **Abenezer Haile** | CTC-017-26 |
| **Dawit Biset** | CTC-1097-26 |
| **Abdurahman Muhidin** | CTC-2354-26 |
| **Yordanos Bisrat** | CTC-1971-26 |
| **Debi Mesfin Shimelis** | CTC-3655-26 |

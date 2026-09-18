# The Adaptive-Defense Closed Loop

> **ROLE / OWNERSHIP**: Backend Engineers & Cybersecurity Researchers  
> **OBJECTIVE**: Detail the end-to-end feedback loop connecting telemetry, detection, investigation, response, and recalculation.  
> **EXPECTED RESULT**: Unbroken automated defense progression from initial probe to verified threat neutralization.

---

## The 12-Step Adaptive Lifecycle

1. **Discovery**: Ingests project topology from Vercel & GitHub.
2. **Digital Twin**: Assembles the graph of assets, routes, roles, and databases.
3. **Assessment**: Flags exposed endpoints and vulnerable packages.
4. **Risk Scoring**: Computes initial quantitative environment risk (e.g. 42.5/100).
5. **Attack-Path Calculation**: Traces viable attack paths from public routes to Tier-0 crown jewels.
6. **Telemetry Ingestion**: Ingests live telemetry events via `@gasha/telemetry-sdk`.
7. **Deterministic Detection**: Flags brute-force or injection signatures matching Cybersecurity rules.
8. **Incident Correlation**: Clusters related detection events into a cohesive Incident.
9. **Investigation Aggregation**: Gathers forensic evidence, timestamps, and graph hops.
10. **AI Grounded Reasoning**: Synthesizes an Attack Story and recommends allowlisted actions.
11. **Controlled Response Execution**: Dispatches `BLOCK_SOURCE` or `DISABLE_SESSION` to target app.
12. **Adaptive Recalculation**: Digital Twin updates, severs the compromised path, and recalculates risk downward.

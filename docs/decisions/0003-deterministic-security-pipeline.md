# ADR 0003: Purely Deterministic Security Pipeline (Exclusion of AI & Live OSINT)

## Status
**Accepted**

## Context
Initial explorations in GASHA and GAS0C considered integrating Large Language Models (LLMs) for incident narrative generation and live external Open Source Intelligence (OSINT) feeds (such as `ip-api.com`, live DNS PTR queries, and third-party reputation APIs) for IP enrichment.

However, comprehensive source auditing identified critical architectural and operational liabilities associated with these integrations:
1. **Live OSINT Liabilities:**
   * Introduces non-deterministic external network latency (often 1–4 seconds per lookup), creating significant bottlenecks in high-throughput ingestion pipelines.
   * Exposes internal network indicators and query telemetry to external third-party services.
   * Subject to third-party rate limits, network outages, and protocol changes.
   * In a closed-network, air-gapped, or competition demonstration setting, external network calls cause timeouts and fragile failures.
2. **AI / LLM Liabilities:**
   * Non-deterministic output: identical inputs can yield divergent classifications, varying confidence scores, and unrepeatable reasoning steps.
   * Hallucination risk: LLMs may hallucinate unobserved attack steps or suggest destructive containment actions without factual grounding.
   * Susceptibility to prompt injection and context poisoning via unsanitized telemetry payloads.
   * High latency, compute requirements, and dependency on local (Ollama) or remote (OpenAI/Anthropic/Gemini) model runtimes.

In an enterprise cybersecurity platform and competition-grade defense system, every detection, investigation finding, and active response containment must be:
* **Strictly reproducible** across environments and test suites.
* **100% offline-capable** with zero external network or model dependencies.
* **Mathematically verifiable** and traceable directly to immutable evidence and telemetry events.
* **Fast and non-blocking**, executing in milliseconds rather than seconds.

## Decision
1. **Full Exclusion of AI & LLMs:**
   * LLMs, generative AI prompt templates, model client SDKs, and probabilistic triage models (including the 151 files currently in `apps/api/app/ai/` and the scikit-learn models in GAS0C) are formally excluded from the final target architecture.
   * No backend detection, investigation, or containment decision shall depend on an LLM or probabilistic model.
2. **Full Exclusion of Live OSINT:**
   * External IP intelligence APIs (`ip-api.com`, AbuseIPDB, VirusTotal), live reverse DNS PTR queries, and external threat feed integrations are formally excluded from the target architecture.
   * Security findings will be derived strictly from:
     * Authorized client environment discovery (GitHub and Vercel metadata).
     * Authoritative runtime telemetry emitted by `@gasha/telemetry-sdk`.
     * Deterministic rule state machines and correlation windows.
     * Static, local rule definitions matching `@gasha/detection-rules`.
3. **Deterministic Investigation & Reporting Engine:**
   * GASHA will adapt the proven `DeterministicIncidentAnalyzer` from GAS0C (`fallback_analysis.py`) into `apps/api/app/investigation/analyzer.py`.
   * The analyzer operates 100% offline, constructing structured technical briefings, chronological investigation steps, affected asset maps, and allowlisted containment actions (`BLOCK_SOURCE`, `DISABLE_SESSION`, `ISOLATE_RESOURCE`).
   * It preserves real-time Server-Sent Events (SSE) and WebSocket progressive streaming (`stream_analysis_chunks`), delivering immediate analyst feedback without model latency.
4. **Controlled Decoupling Policy:**
   * To prevent broken imports or startup failures during migration, the obsolete `apps/api/app/ai/` directory will be retained temporarily as a non-breaking stub until Phase 4 (when the deterministic analyzer is wired into `/api/v1/investigations/`). Once all active dependencies are replaced, the AI package, configuration keys, and unused dependencies will be cleanly removed in Phase 6.

## Consequences
* **Positive:**
  * Eliminates external network failure modes and cloud API costs.
  * Guarantees 100% reproducible test suites and sub-second investigation speed.
  * Ensures zero hallucination risk in active defense containment actions.
  * Completely removes prompt injection attack surfaces.
  * Enables complete offline demonstration capabilities.
* **Negative:**
  * Free-form creative prose narratives are replaced with structured, parameterized, evidence-grounded technical reports.

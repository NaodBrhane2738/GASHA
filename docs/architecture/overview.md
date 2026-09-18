# GASHA System Architecture Overview

> **ROLE / OWNERSHIP**: System Architects & Backend Lead Engineers  
> **OBJECTIVE**: Provide high-level system architecture, component boundaries, and design principles.  
> **EXPECTED RESULT**: Clear technical roadmap for all engineering teams.

---

## 1. Executive Architecture Summary

GASHA is a unified, graph-driven autonomous security platform. It combines static infrastructure discovery from cloud platforms (Vercel, GitHub) with real-time runtime telemetry into a continuous, self-healing **Adaptive-Defense Loop**.

```mermaid
flowchart TD
    Cloud[Vercel & GitHub APIs] -->|Discovery & Normalization| Twin[Digital Twin Security Graph]
    Twin -->|Static Security Checks| SecAssess[Security Assessment]
    SecAssess -->|Criticality & Exposure Weighting| Risk[Risk Engine]
    Risk -->|Graph Traversal & Reachability| AttackPaths[Attack-Path Engine]
    
    TargetApp[Demo Target Application] -->|Telemetry SDK| Ingest[Telemetry Pipeline]
    Ingest -->|Stream Events| Detect[Deterministic Detection Engine]
    Detect -->|Event Clustering| Correlate[Correlation & Incident Engine]
    Correlate -->|Evidence Assembly| Investigate[Investigation Engine]
    
    Investigate -->|Structured Context| AI[AI Grounded Reasoning]
    AI -->|Allowlisted Recommendations| Response[Controlled Response Engine]
    
    Response -->|Block IP / Revoke Session| TargetApp
    Response -->|Mutate Node / Sever Edge| Twin
    Twin -->|Trigger Automatic Recalculation| Risk
```

---

## 2. Key Architecture Tenets
1. **Modular Monolith**: One backend service (`apps/api`), avoiding uncoordinated microservice sprawl.
2. **Deterministic Detection**: Detections are triggered strictly through rule state machines and sliding time windows.
3. **Strict AI Grounding**: LLMs only reason over verified structured evidence. Hallucinations are prohibited.
4. **Allowlisted Response Actions**: Only `BLOCK_SOURCE`, `DISABLE_SESSION`, and `ISOLATE_RESOURCE` are permitted.

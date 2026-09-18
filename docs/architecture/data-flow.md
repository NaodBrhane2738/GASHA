# System Data Flow Specifications

> **ROLE / OWNERSHIP**: Backend & Integration Engineers  
> **OBJECTIVE**: Detail data serialization, message payload routing, and WebSocket events.

---

## 1. Ingestion Pipeline
Target App -> `@gasha/telemetry-sdk` -> `POST /api/v1/telemetry/ingest` -> Async Queue -> Detection Engine.

## 2. Real-Time Broadcast Stream
Backend Event Bus -> WebSocket (`/api/v1/realtime/ws`) -> Next.js Zustand Store -> React UI Components.
- `telemetry.created`: New log arrival
- `detection.created`: Detection rule triggered
- `incident.created`: New incident created
- `risk.updated`: Risk score recalculated
- `response.executed`: Containment action completed

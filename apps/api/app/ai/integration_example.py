"""
==============================================================================
FILE: apps/api/app/ai/integration_example.py
ROLE / OWNERSHIP: AI & Security Intelligence Engineers
OBJECTIVE: Illustrative integration reference for Backend Engineers.
           Demonstrates how the Backend incident triage route or background worker
           should consume the AI Investigation Service safely.
TOOLS & LIBRARIES: asyncio, logging, Pydantic v2
KEY CONCEPTS DEMONSTRATED:
  1. Building InvestigationContext from incident data.
  2. Invoking run_ai_investigation() across the AI boundary.
  3. Handling AI statuses (COMPLETED, INSUFFICIENT_EVIDENCE, FALLBACK, UNAVAILABLE).
  4. Passing advisory recommendations to human analyst queue (NEVER auto-executing).
  5. Checking context staleness / idempotency on telemetry arrival.
NOTE: This is a reference module. It does not alter database or production state.
==============================================================================
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from app.ai.contracts import (
    InvestigationContext,
    IncidentContext,
    EvidenceItem,
    DetectionContext,
    AssetContext,
    AIInvestigationEnvelope,
)
from app.ai.integration import (
    run_ai_investigation,
    is_context_stale,
    format_recommendation_for_backend,
    map_to_backend_investigation_response,
)

logger = logging.getLogger("gasha.ai.example")


async def example_backend_incident_investigation_flow():
    """
    Demonstrates the complete end-to-end flow of how the Backend team
    integrates the AI layer into an incident triage workflow.
    """
    print("--- [1] Assembling Investigation Context from Incident Data ---")
    # Backend constructs the closed-world context from its database & graph stores
    context = InvestigationContext(
        incident=IncidentContext(
            id="INC-2026-0042",
            title="Brute Force Authentication & Admin Account Takeover",
            severity="HIGH",
            status="INVESTIGATING",
            primaryAffectedAssetId="srv-auth-prod",
            relatedAssetIds=["db-customer-prod"],
            detectionEventIds=["DET-AUTH-001"],
            createdAt="2026-09-24T02:00:00Z",
            updatedAt="2026-09-24T02:05:00Z",
            summary="Rapid authentication failures followed by admin privilege usage",
        ),
        evidence=[
            EvidenceItem(
                id="EV-AUTH-01",
                type="TELEMETRY_EVENT",
                source="probe.auth_service",
                timestamp="2026-09-24T02:01:10Z",
                summary="15 failed login attempts for 'admin' from IP 198.51.100.42",
                content={"ip": "198.51.100.42", "user": "admin", "attempts": 15},
                verified=True,
            ),
            EvidenceItem(
                id="EV-AUTH-02",
                type="TELEMETRY_EVENT",
                source="probe.auth_service",
                timestamp="2026-09-24T02:02:00Z",
                summary="Successful login for user 'admin' from IP 198.51.100.42",
                content={"ip": "198.51.100.42", "user": "admin", "sessionId": "sess-admin-999"},
                verified=True,
            ),
        ],
        detections=[
            DetectionContext(
                id="DET-AUTH-001",
                ruleId="RULE-BRUTE-FORCE-01",
                ruleName="High Frequency Authentication Failure Followed by Success",
                description="Detected credential brute force targeting admin",
                severity="HIGH",
                confidence=0.95,
                matchedEventIds=["EV-AUTH-01", "EV-AUTH-02"],
                primaryAssetId="srv-auth-prod",
                timestamp="2026-09-24T02:02:05Z",
                evidenceSummary="Authentication anomaly detected from single remote IP",
            )
        ],
        assets=[
            AssetContext(
                id="srv-auth-prod",
                name="Production Authentication Cluster",
                type="AUTHENTICATION_SERVER",
                criticality="TIER_1_CRITICAL",
                isPubliclyExposed=True,
            ),
            AssetContext(
                id="db-customer-prod",
                name="Primary Customer Database",
                type="DATABASE",
                criticality="TIER_1_CRITICAL",
                isPubliclyExposed=False,
            ),
        ],
    )

    print("--- [2] Calling AI Investigation Service Boundary ---")
    # Backend invokes the AI layer through run_ai_investigation()
    envelope: AIInvestigationEnvelope = await run_ai_investigation(context)

    print(f"Investigation ID:    {envelope.investigationId}")
    print(f"Context Fingerprint: {envelope.contextFingerprint[:16]}...")
    print(f"Investigation Status:{envelope.status}")
    print(f"Is Fallback Used:    {envelope.isFallback}")
    print(f"Assessed Severity:   {envelope.result.severity}")
    print(f"Confidence Score:    {envelope.result.confidence.score:.2f}")

    print("\n--- [3] Interpreting Status for Incident State Lifecycle ---")
    if envelope.status in ("COMPLETED", "SUCCESS"):
        print(">> Status COMPLETED: Store and present full AI analysis to analyst.")
    elif envelope.status == "INSUFFICIENT_EVIDENCE":
        print(">> Status INSUFFICIENT_EVIDENCE: Alert analyst that telemetry is incomplete.")
    elif envelope.status == "FALLBACK":
        print(">> Status FALLBACK: Model error/validation triggered safe deterministic fallback.")
    elif envelope.status in ("UNAVAILABLE", "TIMEOUT"):
        print(">> Status UNAVAILABLE: Local model offline; retain deterministic incident data.")

    print("\n--- [4] Converting Recommendations to Advisory Response Queue ---")
    # Recommendations MUST be routed to human review, NEVER executed autonomously
    for rec in envelope.recommendations:
        backend_action_payload = format_recommendation_for_backend(
            rec, incident_id=context.incident.id
        )
        print(f"Advisory Action Proposal: {backend_action_payload}")
        print("  -> Passed to backend analyst approval drawer (requireManualApproval = True)")

    print("\n--- [5] Idempotency & Staleness Check ---")
    # If new evidence arrives, check whether re-investigation is needed
    stale = is_context_stale(context, envelope)
    print(f"Context has changed since investigation: {stale}")

    print("\n--- [6] Mapping to FastAPI Response Model ---")
    # Helper format matching apps/api/app/schemas/investigation.py: InvestigationResultResponse
    api_response = map_to_backend_investigation_response(envelope, context)
    print(f"Generated API response keys: {list(api_response.keys())}")


if __name__ == "__main__":
    asyncio.run(example_backend_incident_investigation_flow())

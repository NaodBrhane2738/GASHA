"""
==============================================================================
FILE: apps/api/app/workers/recalculation.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Background and triggered recalculation orchestrator for Security Assessment,
Attack Paths, and Risk Scoring.
TRIGGERS:
  - Discovery sync completed
  - Security assessment execution
  - Verified active response execution (IP block, session invalidate, asset isolate)
==============================================================================
"""

import logging
from typing import Dict, Any

from app.security_assessment.engine import get_assessment_engine
from app.attack_paths.service import get_attack_path_service
from app.risk.service import get_risk_service

logger = logging.getLogger("gasha.workers.recalculation")


def recalculate_environment_security_state(
    environment_id: str,
    trigger_event: str = "MANUAL_TRIGGER"
) -> Dict[str, Any]:
    """
    Coordinates the full deterministic pipeline recalculation:
      1. Security Assessment findings
      2. Digital Twin Attack Path discovery & reachability
      3. Environment Risk Scoring & Explainability
    """
    logger.info(f"Triggering security recalculation for {environment_id} (Reason: {trigger_event})")

    # 1. Assessment
    assessment_engine = get_assessment_engine()
    assessment_summary = assessment_engine.run_assessment(environment_id=environment_id)

    # 2. Attack Paths
    path_service = get_attack_path_service()
    paths = path_service.recalculate_attack_paths(environment_id=environment_id)

    # 3. Risk Calculation
    risk_service = get_risk_service()
    risk_score = risk_service.recalculate_risk(environment_id=environment_id)

    logger.info(
        f"Recalculation complete for {environment_id}: "
        f"{assessment_summary.findingsCount} findings, "
        f"{len(paths)} attack paths, "
        f"Risk Score: {risk_score.overallScore}/100"
    )

    return {
        "environmentId": environment_id,
        "triggerEvent": trigger_event,
        "status": "COMPLETED",
        "findingsCount": assessment_summary.findingsCount,
        "activeAttackPathsCount": len(paths),
        "riskScore": risk_score.overallScore,
        "calculatedAt": risk_score.calculatedAt
    }


async def run_periodic_snapshot():
    """Periodic job for scheduled maintenance."""
    logger.info("Executing periodic risk recalculation across active environments")
    recalculate_environment_security_state("env-prod", trigger_event="PERIODIC_SNAPSHOT")

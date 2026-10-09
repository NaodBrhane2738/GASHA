"""
==============================================================================
FILE: apps/api/app/api/vulnerabilities.py
ROLE / OWNERSHIP: Backend & Cybersecurity Engineers
OBJECTIVE: Operational REST API for listing, filtering, and triggering security assessments.
STRICT ISOLATION: Scoped strictly by environmentId.
==============================================================================
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status

from app.core.auth import get_current_user, enforce_environment_boundary
from app.db.repositories.vulnerability_repository import get_vulnerability_repository
from app.schemas.vulnerability import (
    VulnerabilityResponse,
    AssessmentSummaryResponse
)
from app.security_assessment.engine import get_assessment_engine
from app.workers.recalculation import recalculate_environment_security_state

logger = logging.getLogger("gasha.api.vulnerabilities")
router = APIRouter()


@router.get("", response_model=List[VulnerabilityResponse], summary="List Security Vulnerabilities")
async def list_vulnerabilities(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    asset_id: Optional[str] = Query(None, alias="assetId"),
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query("OPEN", alias="status"),
    category: Optional[str] = Query(None),
    user: dict = Depends(get_current_user)
) -> List[VulnerabilityResponse]:
    """
    Returns list of discovered vulnerabilities and configuration weaknesses strictly for authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_vulnerability_repository()
    
    findings = repo.list_findings(
        environment_id=auth_env,
        asset_id=asset_id,
        severity=severity.upper() if severity else None,
        status=status_filter.upper() if status_filter else None,
        category=category.upper() if category else None
    )
    return findings


@router.post("/assess", response_model=AssessmentSummaryResponse, summary="Run Security Assessment")
async def run_assessment(
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> AssessmentSummaryResponse:
    """
    Executes deterministic security assessment rules across all authorized environment assets,
    updates finding lifecycles, and triggers risk and attack-path recalculation.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    engine = get_assessment_engine()
    summary = engine.run_assessment(environment_id=auth_env)

    # Recalculate downstream graph and risk state
    recalculate_environment_security_state(auth_env, trigger_event="ASSESSMENT_RUN")
    return summary


@router.get("/{vuln_id}", response_model=VulnerabilityResponse, summary="Get Vulnerability Detail")
async def get_vulnerability(
    vuln_id: str,
    environment_id: Optional[str] = Query(None, alias="environmentId"),
    user: dict = Depends(get_current_user)
) -> VulnerabilityResponse:
    """
    Returns details and evidence for a specific vulnerability finding within authorized environment.
    """
    auth_env = enforce_environment_boundary(user, environment_id)
    repo = get_vulnerability_repository()
    finding = repo.get_finding(vuln_id, auth_env)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{vuln_id}' not found in environment '{auth_env}'"
        )
    return finding

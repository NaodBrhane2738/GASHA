"""
==============================================================================
FILE: apps/api/app/api/soc.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Read/act API for the SOC dashboard: metrics, incidents, findings, root-cause
           analysis, mitigation release, and a Server-Sent Events stream of bus events.
EXPECTED RESULTS / BEHAVIOR:
  - All routes require an authenticated analyst (bearer JWT). The SSE stream is consumed
    with fetch() so the token travels in the Authorization header, never in the URL.
==============================================================================
"""

import asyncio
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from app.adaptive.remediation import analyze
from app.adaptive.soc_runtime import SocRuntime
from app.core.auth import get_current_user
from app.core.errors import EntityNotFoundException
from app.schemas.soc import Finding, FindingAnalysis, Incident, MetricsSnapshot, Mitigation

router = APIRouter(dependencies=[Depends(get_current_user)])


def runtime(request: Request) -> SocRuntime:
    return request.app.state.soc


@router.get("/metrics", response_model=MetricsSnapshot)
async def get_metrics(window: int = Query(300, ge=10, le=600), soc: SocRuntime = Depends(runtime)):
    return soc.pipeline.snapshot(window)


@router.get("/incidents", response_model=List[Incident])
async def list_incidents(status: Optional[str] = Query(None, pattern="^(OPEN|MITIGATED|RESOLVED)$"),
                         limit: int = Query(100, ge=1, le=500), soc: SocRuntime = Depends(runtime)):
    return soc.pipeline.incidents.list(status, limit)


@router.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str, soc: SocRuntime = Depends(runtime)):
    inc = soc.pipeline.incidents.get(incident_id)
    if not inc:
        raise EntityNotFoundException("Incident", incident_id)
    return inc


@router.get("/findings", response_model=List[Finding])
async def list_findings(source: Optional[str] = None, limit: int = Query(100, ge=1, le=1000),
                        soc: SocRuntime = Depends(runtime)):
    return soc.pipeline.list_findings(limit, source)


@router.get("/findings/{finding_id}/analysis", response_model=FindingAnalysis)
async def get_finding_analysis(finding_id: str, soc: SocRuntime = Depends(runtime)):
    f = soc.pipeline.get_finding(finding_id)
    if not f:
        raise EntityNotFoundException("Finding", finding_id)
    related = [x for x in soc.pipeline.list_findings(20, f.sourceKey) if x.id != f.id][:10]
    return analyze(f, related)


@router.get("/mitigations", response_model=List[Mitigation])
async def list_mitigations(soc: SocRuntime = Depends(runtime)):
    return soc.pipeline.policy.active_mitigations()


@router.delete("/mitigations/{source_key}", response_model=Mitigation)
async def release_mitigation(source_key: str, soc: SocRuntime = Depends(runtime)):
    m = soc.pipeline.release(source_key)
    if not m:
        raise EntityNotFoundException("Mitigation", source_key)
    return m


@router.get("/stream")
async def stream(request: Request, soc: SocRuntime = Depends(runtime)):
    q = soc.bus.subscribe()

    async def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        break
                    yield ": keep-alive\n\n"
                    continue
                yield f"id: {event.id}\nevent: {event.type}\ndata: {event.model_dump_json()}\n\n"
        finally:
            soc.bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

"""
==============================================================================
FILE: apps/api/app/adaptive/incidents.py
ROLE / OWNERSHIP: Backend Engineers
OBJECTIVE: Correlates findings and policy actions per source into incidents and tracks the
           response lifecycle: INGESTED -> DETECTED -> ENFORCED -> MITIGATED (-> RESOLVED).
EXPECTED RESULTS / BEHAVIOR:
  - At most one open incident per source; severity only ever escalates.
  - Flag-only incidents auto-resolve after a quiet period; enforced incidents resolve when
    their mitigation expires or is released by an analyst.
==============================================================================
"""

import time
import uuid
from collections import OrderedDict
from typing import Callable, Dict, List, Optional

from app.core.events import utc_iso
from app.schemas.soc import SEVERITY_RANK, Finding, Incident, LifecycleStep, Mitigation

STAGE_ORDER = {"INGESTED": 0, "DETECTED": 1, "ENFORCED": 2, "MITIGATED": 3}


class IncidentTracker:
    def __init__(self, max_incidents: int = 500, quiet_resolve_seconds: int = 1800,
                 clock: Callable[[], float] = time.time):
        self._incidents: "OrderedDict[str, Incident]" = OrderedDict()
        self._open_by_source: Dict[str, str] = {}
        self._max = max_incidents
        self._quiet = quiet_resolve_seconds
        self._clock = clock

    def _now(self) -> str:
        return utc_iso(self._clock())

    def _advance(self, inc: Incident, stage: str, detail: str) -> None:
        now = self._now()
        inc.steps.append(LifecycleStep(stage=stage, at=now, detail=detail))
        if STAGE_ORDER[stage] > STAGE_ORDER[inc.stage]:
            inc.stage = stage
        inc.updatedAt = now

    def _escalate(self, inc: Incident, severity: str) -> None:
        if SEVERITY_RANK[severity] > SEVERITY_RANK[inc.severity]:
            inc.severity = severity

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def open_for(self, source: str) -> Optional[Incident]:
        iid = self._open_by_source.get(source)
        return self._incidents.get(iid) if iid else None

    def list(self, status: Optional[str] = None, limit: int = 100) -> List[Incident]:
        items = [i for i in reversed(self._incidents.values()) if not status or i.status == status]
        return items[:limit]

    def ensure(self, source: str, title: str, severity: str, ingest_detail: str) -> Incident:
        inc = self.open_for(source)
        if inc:
            self._escalate(inc, severity)
            return inc
        now = self._now()
        inc = Incident(
            id=f"inc-{uuid.uuid4().hex[:10]}", sourceKey=source, title=title, severity=severity,
            status="OPEN", stage="INGESTED",
            steps=[LifecycleStep(stage="INGESTED", at=now, detail=ingest_detail)],
            openedAt=now, updatedAt=now,
        )
        self._incidents[inc.id] = inc
        self._open_by_source[source] = inc.id
        while len(self._incidents) > self._max:
            old_id, old = self._incidents.popitem(last=False)
            if self._open_by_source.get(old.sourceKey) == old_id:
                del self._open_by_source[old.sourceKey]
        return inc

    def record_detection(self, inc: Incident, finding: Finding) -> None:
        inc.findingIds.append(finding.id)
        self._escalate(inc, finding.severity)
        self._advance(inc, "DETECTED", f"{finding.ruleId}: {finding.category} in {finding.location}"
                      + (f" ({finding.field})" if finding.field else ""))

    def record_enforcement(self, inc: Incident, mitigation: Mitigation) -> None:
        inc.mitigation = mitigation
        self._escalate(inc, mitigation.severity)
        code = 423 if mitigation.action == "LOCK" else 429
        self._advance(inc, "ENFORCED", f"{mitigation.action} (HTTP {code}) via {mitigation.ruleId}: {mitigation.reason}")

    def record_block(self, inc: Incident) -> None:
        inc.blockedRequests += 1
        if inc.stage != "MITIGATED":
            inc.status = "MITIGATED"
            self._advance(inc, "MITIGATED", "Policy actively rejecting traffic from source")
        else:
            inc.updatedAt = self._now()

    def resolve(self, source: str, detail: str) -> Optional[Incident]:
        inc = self.open_for(source)
        if not inc:
            return None
        now = self._now()
        inc.status = "RESOLVED"
        inc.resolvedAt = now
        inc.updatedAt = now
        inc.steps.append(LifecycleStep(stage=inc.stage, at=now, detail=f"Resolved: {detail}"))
        del self._open_by_source[source]
        return inc

    def sweep_quiet(self) -> List[Incident]:
        """Resolve flag-only incidents that have been quiet for the configured period."""
        cutoff = utc_iso(self._clock() - self._quiet)
        out = []
        for source, iid in list(self._open_by_source.items()):
            inc = self._incidents[iid]
            if inc.mitigation is None and inc.updatedAt < cutoff:
                out.append(self.resolve(source, "no further activity"))
        return out

    def counts(self) -> Dict[str, int]:
        """Funnel: how many retained incidents reached each lifecycle stage, plus how many resolved."""
        c = {"INGESTED": 0, "DETECTED": 0, "ENFORCED": 0, "MITIGATED": 0, "RESOLVED": 0}
        for inc in self._incidents.values():
            for stage in {s.stage for s in inc.steps}:
                c[stage] += 1
            if inc.status == "RESOLVED":
                c["RESOLVED"] += 1
        return c

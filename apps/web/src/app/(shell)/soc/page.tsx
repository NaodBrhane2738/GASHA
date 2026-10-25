'use client';

import { Suspense, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { Card } from '@/components/ui/card';
import { useSocFindings, useSocIncidents, useSocMetrics } from '@/lib/soc/queries';
import { useSocStream } from '@/lib/soc/useSocStream';
import { IncidentTimeline, LifecycleFlow } from '@/components/soc/LifecycleFlow';
import { Legend, RequestVolumeChart, SourceRateChart } from '@/components/soc/TrafficCharts';
import { MitigationsPanel } from '@/components/soc/MitigationsPanel';
import { IncidentList } from '@/components/soc/IncidentList';
import { AnalysisPanel, FindingsFeed } from '@/components/soc/AnalysisPanel';
import type { LifecycleStage, SocIncident } from '@/types/soc';

export default function SocPageRoute() {
  return (
    <Suspense>
      <SocPage />
    </Suspense>
  );
}

function SocPage() {
  // Deep link from alert emails / policy banner: /soc?incident=inc-...
  const linked = useSearchParams().get('incident');
  const { data: metrics } = useSocMetrics();
  const { data: incidents = [] } = useSocIncidents();
  const { data: findings = [] } = useSocFindings();

  const [incidentId, setIncidentId] = useState<string | null>(linked);
  const [findingId, setFindingId] = useState<string | null>(null);
  const [pulse, setPulse] = useState<LifecycleStage | null>(null);
  const pulseTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const { connected } = useSocStream((ev) => {
    if (ev.type !== 'incident.updated') return;
    setPulse((ev.data as SocIncident).stage);
    clearTimeout(pulseTimer.current);
    pulseTimer.current = setTimeout(() => setPulse(null), 1200);
  });

  const incident = incidents.find((i) => i.id === incidentId) ?? null;
  const visibleFindings = useMemo(
    () => (incident ? findings.filter((f) => f.incidentId === incident.id) : findings),
    [findings, incident],
  );

  const series = metrics?.series ?? [];
  const totals = metrics?.totals ?? {};
  const last60 = series.slice(-60);
  const sum = (k: 'total' | 'throttled' | 'locked') => series.reduce((n, b) => n + b[k], 0);
  const stageCounts = {
    INGESTED: totals.stageIngested,
    DETECTED: totals.stageDetected,
    ENFORCED: totals.stageEnforced,
    MITIGATED: totals.stageMitigated,
    RESOLVED: totals.stageResolved,
  };

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h2 className="text-[13px] font-semibold">Security Operations Center</h2>
          <p className="text-[11px] text-muted-foreground">Real-time policy enforcement, incident lifecycle and remediation</p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span
            className="inline-block size-2 rounded-full"
            style={{ background: connected ? 'hsl(var(--low))' : 'hsl(var(--medium))' }}
            aria-hidden
          />
          {connected ? 'live' : 'reconnecting…'}
        </div>
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <Kpi label="Requests · last 60s" value={last60.reduce((n, b) => n + b.total, 0)} />
        <Kpi label="Requests · 5 min" value={sum('total')} />
        <Kpi label="Throttled 429 · 5 min" value={sum('throttled')} />
        <Kpi label="Locked 423 · 5 min" value={sum('locked')} />
        <Kpi label="Active mitigations" value={metrics?.activeMitigations.length ?? 0} />
      </div>

      <div className="grid grid-cols-12 gap-4">
        <Card className="col-span-12 p-4">
          <SectionTitle>Incident response lifecycle</SectionTitle>
          <LifecycleFlow counts={stageCounts} pulse={pulse} incident={incident} />
          <div className="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="max-h-[300px] overflow-y-auto rounded-md border">
              <IncidentList
                items={incidents}
                selectedId={incidentId}
                onSelect={(id) => {
                  setIncidentId(id === incidentId ? null : id);
                  setFindingId(null);
                }}
              />
            </div>
            <IncidentTimeline incident={incident} />
          </div>
        </Card>

        <Card className="col-span-12 p-4 xl:col-span-8">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <SectionTitle className="mb-0">Request volume by decision</SectionTitle>
            <Legend />
          </div>
          <RequestVolumeChart series={series} />
          <div className="mt-4">
            <SectionTitle>
              Peak per-source rate vs limit
              {metrics && (
                <span className="ml-2 font-normal normal-case text-muted-foreground">
                  {metrics.policy.limit} req / {metrics.policy.windowSeconds}s · lock after{' '}
                  {metrics.policy.escalationCount} violations
                </span>
              )}
            </SectionTitle>
            {metrics && (
              <SourceRateChart series={series} limit={metrics.policy.limit} windowSeconds={metrics.policy.windowSeconds} />
            )}
          </div>
        </Card>

        <Card className="col-span-12 p-4 xl:col-span-4">
          <SectionTitle>Active mitigations</SectionTitle>
          <MitigationsPanel items={metrics?.activeMitigations ?? []} />
          <div className="mt-4">
            <SectionTitle>Top sources · current window</SectionTitle>
            <table className="w-full text-[11.5px]">
              <tbody>
                {(metrics?.topSources ?? []).map((s) => (
                  <tr key={s.sourceKey} className="border-b last:border-0">
                    <td className="py-1 font-mono">{s.sourceKey}</td>
                    <td className="py-1 text-right font-mono">
                      {s.requestsInWindow}
                      <span className="text-muted-foreground"> / {metrics?.policy.limit}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card className="col-span-12 p-4 lg:col-span-5">
          <SectionTitle>
            Flagged requests
            {incident && <span className="ml-2 font-normal normal-case text-muted-foreground">for {incident.id}</span>}
          </SectionTitle>
          <div className="max-h-[520px] overflow-y-auto">
            <FindingsFeed items={visibleFindings} selectedId={findingId} onSelect={setFindingId} />
          </div>
        </Card>

        <Card className="col-span-12 p-4 lg:col-span-7">
          <SectionTitle>Remediation &amp; analysis</SectionTitle>
          <AnalysisPanel findingId={findingId} />
        </Card>
      </div>
    </div>
  );
}

function Kpi({ label, value }: { label: string; value: number }) {
  return (
    <Card className="px-3 py-2.5">
      <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-mono text-[22px] leading-tight">{value.toLocaleString()}</div>
    </Card>
  );
}

function SectionTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <h3 className={`mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground ${className ?? ''}`}>
      {children}
    </h3>
  );
}

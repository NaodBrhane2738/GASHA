'use client';

import { Suspense, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Mail, ShieldCheck } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { useSocView } from '@/lib/api/queries';
import { IncidentTimeline, LifecycleFlow } from '@/components/soc/LifecycleFlow';
import { LatencyChart, LatencyLegend, Legend, RequestVolumeChart, SourceRateChart } from '@/components/soc/TrafficCharts';
import { MitigationsPanel } from '@/components/soc/MitigationsPanel';
import { IncidentList } from '@/components/soc/IncidentList';
import { AnalysisPanel, FindingsFeed } from '@/components/soc/AnalysisPanel';
import { RequestLogTable } from '@/components/soc/RequestLogTable';
import { fmtTime, socSeverityColor } from '@/components/soc/meta';
import type { LifecycleStage } from '@/types/soc';

export default function SocPageRoute() {
  return (
    <Suspense>
      <SocPage />
    </Suspense>
  );
}

function SocPage() {
  const linked = useSearchParams().get('incident');
  const view = useSocView();
  const [incidentId, setIncidentId] = useState<string | null>(linked);
  const [findingId, setFindingId] = useState<string | null>(null);
  const [pulse, setPulse] = useState<LifecycleStage | null>(null);
  const lastUpdate = useRef<string>('');

  const state = view?.state;
  const incidents = useMemo(() => state?.incidents ?? [], [state]);
  const findings = useMemo(() => state?.findings ?? [], [state]);

  // Follow the deep link, otherwise auto-select the newest incident so the panels are never blank.
  const effectiveIncidentId = incidentId ?? incidents[0]?.id ?? null;
  const incident = incidents.find((i) => i.id === effectiveIncidentId) ?? null;
  const visibleFindings = useMemo(
    () => (incident ? findings.filter((f) => f.incidentId === incident.id) : findings),
    [findings, incident],
  );
  const effectiveFindingId = findingId ?? visibleFindings[0]?.id ?? null;

  // Briefly highlight the lifecycle stage that just changed.
  useEffect(() => {
    const top = incidents[0];
    if (!top) return;
    const sig = `${top.id}|${top.updatedAt}`;
    if (lastUpdate.current && lastUpdate.current !== sig) {
      lastUpdate.current = sig;
      const show = setTimeout(() => setPulse(top.stage), 0);
      const hide = setTimeout(() => setPulse(null), 1200);
      return () => {
        clearTimeout(show);
        clearTimeout(hide);
      };
    }
    lastUpdate.current = sig;
  }, [incidents]);

  if (!view || !state) {
    return <div className="p-6 text-[12px] text-muted-foreground">Starting telemetry pipeline…</div>;
  }

  const series = state.series;
  const last60 = series.slice(-60);
  const sum = (k: 'total' | 'throttled' | 'locked') => series.reduce((n, b) => n + b[k], 0);
  const withLatency = last60.filter((b) => b.latencyP95);
  const p95 = Math.round(withLatency.reduce((n, b) => n + (b.latencyP95 ?? 0), 0) / Math.max(1, withLatency.length));

  return (
    <div className="h-full overflow-y-auto p-3 sm:p-4 lg:h-[calc(100vh-100px)]">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-[13px] font-semibold">Security Operations Center</h2>
          <p className="text-[11px] text-muted-foreground">
            Real-time policy enforcement for the GASHA Market sandbox store · deterministic rules, no AI in the decision path
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span className="inline-block size-2 animate-pulse rounded-full bg-[hsl(var(--low))]" aria-hidden />
          live · risk <span className="font-mono text-foreground">{view.riskNow}</span>
        </div>
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Requests · last 60s" value={last60.reduce((n, b) => n + b.total, 0)} />
        <Kpi label="Requests · 5 min" value={sum('total')} />
        <Kpi label="Throttled 429 · 5 min" value={sum('throttled')} tone="hsl(var(--high))" />
        <Kpi label="Locked 423 · 5 min" value={sum('locked')} tone="hsl(var(--critical))" />
        <Kpi label="Latency p95 · 60s" value={p95} suffix="ms" />
        <Kpi label="Active mitigations" value={state.mitigations.length} />
      </div>

      <div className="grid grid-cols-12 gap-4">
        <Card className="col-span-12 p-4">
          <SectionTitle>Incident response lifecycle</SectionTitle>
          <LifecycleFlow counts={view.stageCounts} pulse={pulse} incident={incident} />
          <div className="mt-3 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="max-h-[300px] overflow-y-auto rounded-md border">
              <IncidentList
                items={incidents}
                selectedId={effectiveIncidentId}
                onSelect={(id) => {
                  setIncidentId(id);
                  setFindingId(null);
                }}
              />
            </div>
            <div className="space-y-2">
              <IncidentTimeline incident={incident} />
              {incident && (
                <div className="flex flex-wrap gap-3 text-[11px]">
                  <Link href={`/incidents/${incident.id}`} className="text-primary hover:underline">Reconstruct attack story →</Link>
                  <Link href="/response" className="text-primary hover:underline">Response actions →</Link>
                  {incident.pathId && <Link href="/paths" className="text-primary hover:underline">Attack path {incident.pathId} →</Link>}
                </div>
              )}
            </div>
          </div>
        </Card>

        <Card className="col-span-12 p-4 xl:col-span-8">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <SectionTitle className="mb-0">Request volume by decision</SectionTitle>
            <Legend />
          </div>
          <RequestVolumeChart series={series} />
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <div>
              <SectionTitle>
                Peak per-source rate vs limit
                <span className="ml-2 font-normal normal-case text-muted-foreground">
                  {view.policy.limit} req / {view.policy.windowSeconds}s
                </span>
              </SectionTitle>
              <SourceRateChart series={series} limit={view.policy.limit} windowSeconds={view.policy.windowSeconds} />
            </div>
            <div>
              <div className="mb-2 flex items-center justify-between">
                <SectionTitle className="mb-0">Latency</SectionTitle>
                <LatencyLegend />
              </div>
              <LatencyChart series={series} />
            </div>
          </div>
        </Card>

        <Card className="col-span-12 p-4 xl:col-span-4">
          <SectionTitle>Active mitigations</SectionTitle>
          {state.mitigations.length ? (
            <MitigationsPanel items={state.mitigations} />
          ) : (
            <div className="flex items-center gap-2 rounded-md border border-dashed px-3 py-4 text-[11.5px] text-muted-foreground">
              <ShieldCheck className="size-4 text-[hsl(var(--low))]" /> All clear — no source is throttled or locked.
            </div>
          )}
          <div className="mt-4">
            <SectionTitle>Top sources · current window</SectionTitle>
            <table className="w-full text-[11.5px]">
              <tbody>
                {view.topSources.map((s) => (
                  <tr key={s.sourceKey} className="border-b last:border-0">
                    <td className="py-1 font-mono">{s.sourceKey}</td>
                    <td className="py-1 text-right font-mono">
                      <span style={{ color: s.requestsInWindow > view.policy.limit ? 'hsl(var(--high))' : undefined }}>{s.requestsInWindow}</span>
                      <span className="text-muted-foreground"> / {view.policy.limit}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4">
            <SectionTitle>Alert dispatch</SectionTitle>
            <ul className="space-y-1.5">
              {state.alerts.slice(0, 5).map((a) => (
                <li key={a.id} className="flex items-start gap-2 text-[11px]">
                  <Mail className="mt-0.5 size-3.5 shrink-0" style={{ color: socSeverityColor(a.severity) }} aria-hidden />
                  <div className="min-w-0">
                    <div className="truncate" title={a.subject}>{a.subject}</div>
                    <div className="text-[10px] text-muted-foreground">
                      {fmtTime(a.ts)} · emailed {a.to} · {a.status}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </Card>

        <Card className="col-span-12 p-4">
          <SectionTitle>Request log · live</SectionTitle>
          <RequestLogTable rows={state.requests.slice(0, 40)} />
        </Card>

        <Card className="col-span-12 p-4 lg:col-span-5">
          <SectionTitle>
            Flagged requests
            {incident && <span className="ml-2 font-normal normal-case text-muted-foreground">for {incident.id}</span>}
          </SectionTitle>
          <div className="max-h-[520px] overflow-y-auto">
            <FindingsFeed items={visibleFindings} selectedId={effectiveFindingId} onSelect={setFindingId} />
          </div>
        </Card>

        <Card className="col-span-12 p-4 lg:col-span-7">
          <SectionTitle>Remediation &amp; analysis</SectionTitle>
          <AnalysisPanel findingId={effectiveFindingId} />
        </Card>
      </div>
    </div>
  );
}

function Kpi({ label, value, suffix, tone }: { label: string; value: number; suffix?: string; tone?: string }) {
  return (
    <Card className="px-3 py-2.5">
      <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-mono text-[22px] leading-tight" style={{ color: value && tone ? tone : undefined }}>
        {value.toLocaleString()}
        {suffix && <span className="ml-0.5 text-[12px] text-muted-foreground">{suffix}</span>}
      </div>
    </Card>
  );
}

function SectionTitle({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <h3 className={`mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground ${className ?? ''}`}>{children}</h3>
  );
}

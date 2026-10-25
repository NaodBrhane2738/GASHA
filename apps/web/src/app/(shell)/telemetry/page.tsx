'use client';

import { useMemo, useState } from 'react';
import { Card } from '@/components/ui/card';
import { useSim } from '@/lib/sim/runtime';
import { RequestLogTable } from '@/components/soc/RequestLogTable';
import { LatencyChart, LatencyLegend, Legend, RequestVolumeChart } from '@/components/soc/TrafficCharts';
import { cn } from '@/lib/utils';
import type { RequestLog } from '@/lib/sim/engine';

const FILTERS: { key: 'all' | 'blocked' | 'flagged'; label: string; test: (r: RequestLog) => boolean }[] = [
  { key: 'all', label: 'All', test: () => true },
  { key: 'blocked', label: 'Blocked (429/423)', test: (r) => r.action === 'THROTTLE' || r.action === 'LOCK' },
  { key: 'flagged', label: 'Flagged', test: (r) => r.action === 'FLAG' },
];

export default function TelemetryPage() {
  const state = useSim((s) => s.state);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]['key']>('all');

  const rows = useMemo(() => {
    const f = FILTERS.find((x) => x.key === filter)!;
    return (state?.requests ?? []).filter(f.test).slice(0, 80);
  }, [state, filter]);

  const endpoints = useMemo(() => {
    const m = new Map<string, { path: string; count: number; blocked: number; latency: number[] }>();
    for (const r of state?.requests ?? []) {
      const path = r.path.split('?')[0].replace(/\/p-\d+$/, '/:id');
      const e = m.get(path) ?? { path, count: 0, blocked: 0, latency: [] };
      e.count += 1;
      if (r.action === 'THROTTLE' || r.action === 'LOCK') e.blocked += 1;
      else e.latency.push(r.latencyMs);
      m.set(path, e);
    }
    return [...m.values()].sort((a, b) => b.count - a.count);
  }, [state]);

  if (!state) return <div className="p-6 text-[12px] text-muted-foreground">Connecting to telemetry…</div>;

  return (
    <div className="h-full overflow-y-auto p-3 sm:p-4 lg:h-[calc(100vh-100px)]">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-[13px] font-semibold">Live Telemetry</h2>
          <p className="text-[11px] text-muted-foreground">Every request to the GASHA Market sandbox, classified by deterministic rules</p>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span className="inline-block size-2 animate-pulse rounded-full bg-[hsl(var(--low))]" /> streaming
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card className="p-4">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Requests per 10s</h3>
            <Legend />
          </div>
          <RequestVolumeChart series={state.series} />
        </Card>
        <Card className="p-4">
          <div className="mb-2 flex items-center justify-between">
            <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Latency</h3>
            <LatencyLegend />
          </div>
          <LatencyChart series={state.series} />
        </Card>
      </div>

      <Card className="mt-4 p-4">
        <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Endpoints · recent window</h3>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-[11.5px]">
            <thead className="text-left text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr className="border-b">
                <th className="py-1.5 font-medium">Endpoint</th>
                <th className="py-1.5 text-right font-medium">Requests</th>
                <th className="py-1.5 text-right font-medium">Blocked</th>
                <th className="py-1.5 text-right font-medium">Avg latency</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((e) => (
                <tr key={e.path} className="border-b last:border-0">
                  <td className="py-1 font-mono">{e.path}</td>
                  <td className="py-1 text-right font-mono">{e.count}</td>
                  <td className="py-1 text-right font-mono" style={{ color: e.blocked ? 'hsl(var(--high))' : undefined }}>{e.blocked}</td>
                  <td className="py-1 text-right font-mono text-muted-foreground">
                    {e.latency.length ? Math.round(e.latency.reduce((a, b) => a + b, 0) / e.latency.length) : '—'} ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card className="mt-4 p-4">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Request stream</h3>
          <div className="flex gap-1" role="tablist">
            {FILTERS.map((f) => (
              <button
                key={f.key}
                role="tab"
                aria-selected={filter === f.key}
                onClick={() => setFilter(f.key)}
                className={cn(
                  'rounded-md border px-2 py-0.5 text-[11px]',
                  filter === f.key ? 'border-primary/50 bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-secondary',
                )}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>
        {rows.length ? (
          <RequestLogTable rows={rows} />
        ) : (
          <div className="rounded-md border border-dashed px-3 py-6 text-center text-[11.5px] text-muted-foreground">
            No {filter} requests in the current window — trigger a scenario from Demo control to see enforcement here.
          </div>
        )}
      </Card>
    </div>
  );
}

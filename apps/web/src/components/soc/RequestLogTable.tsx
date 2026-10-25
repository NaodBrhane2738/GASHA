'use client';

import type { RequestLog } from '@/lib/sim/engine';
import { fmtTime } from './meta';

const ACTION_STYLE: Record<RequestLog['action'], { label: string; color: string }> = {
  ALLOW: { label: 'allow', color: 'hsl(var(--muted-foreground))' },
  FLAG: { label: 'flag', color: 'hsl(var(--medium))' },
  THROTTLE: { label: '429', color: 'hsl(var(--high))' },
  LOCK: { label: '423', color: 'hsl(var(--critical))' },
};

const statusColor = (s: number) =>
  s >= 500 ? 'hsl(var(--critical))' : s === 423 ? 'hsl(var(--critical))' : s >= 400 ? 'hsl(var(--high))' : 'hsl(var(--muted-foreground))';

export function RequestLogTable({ rows }: { rows: RequestLog[] }) {
  return (
    <div className="max-h-[320px] overflow-auto rounded-md border">
      <table className="w-full min-w-[640px] text-[11.5px]">
        <thead className="sticky top-0 bg-card text-left text-[10px] uppercase tracking-wide text-muted-foreground">
          <tr className="border-b">
            <th className="px-2 py-1.5 font-medium">Time</th>
            <th className="px-2 py-1.5 font-medium">Source</th>
            <th className="px-2 py-1.5 font-medium">Request</th>
            <th className="px-2 py-1.5 text-right font-medium">Status</th>
            <th className="px-2 py-1.5 text-right font-medium">Latency</th>
            <th className="px-2 py-1.5 font-medium">Decision</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const a = ACTION_STYLE[r.action];
            return (
              <tr key={r.id} className={`border-b last:border-0 ${r.action === 'ALLOW' ? '' : 'bg-secondary/30'}`}>
                <td className="whitespace-nowrap px-2 py-1 font-mono text-[10.5px] text-muted-foreground">{fmtTime(r.ts)}</td>
                <td className="whitespace-nowrap px-2 py-1 font-mono">
                  {r.ip}
                  <span className="ml-1 text-[10px] text-muted-foreground">{r.visitor ? 'you' : r.country}</span>
                </td>
                <td className="max-w-[340px] truncate px-2 py-1 font-mono" title={`${r.method} ${r.path}`}>
                  <span className="text-muted-foreground">{r.method}</span> {r.path}
                </td>
                <td className="px-2 py-1 text-right font-mono" style={{ color: statusColor(r.status) }}>{r.status}</td>
                <td className="px-2 py-1 text-right font-mono text-muted-foreground">{r.latencyMs}ms</td>
                <td className="whitespace-nowrap px-2 py-1">
                  <span className="font-mono text-[10.5px] font-semibold" style={{ color: a.color }}>{a.label}</span>
                  {r.ruleId && <span className="ml-1.5 font-mono text-[10px] text-muted-foreground">{r.ruleId}</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

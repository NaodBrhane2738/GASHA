'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Lock, Timer, X } from 'lucide-react';
import { useSim } from '@/lib/sim/runtime';
import { fmtRemaining } from './meta';

/**
 * Live enforcement banner: announces the most recent HTTP 429 / 423 policy action across every
 * page, with the Retry-After countdown and a link to the incident.
 */
export function PolicyBanner() {
  const latest = useSim((s) => {
    const ms = s.state?.mitigations ?? [];
    return ms.reduce<(typeof ms)[number] | null>((a, m) => (!a || m.createdAt > a.createdAt ? m : a), null);
  });
  const incidentId = useSim((s) => s.state?.incidents.find((i) => i.sourceKey === latest?.sourceKey && i.status !== 'RESOLVED')?.id);
  const [dismissed, setDismissed] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  if (!latest) return null;
  const key = `${latest.sourceKey}|${latest.createdAt}`;
  const expires = new Date(latest.expiresAt).getTime();
  if (dismissed === key || expires <= now) return null;

  const locked = latest.action === 'LOCK';
  const color = locked ? 'hsl(var(--critical))' : 'hsl(var(--high))';
  const Icon = locked ? Lock : Timer;

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b px-3 py-2 text-[12px] sm:px-4"
      style={{ background: `color-mix(in srgb, ${color} 12%, transparent)`, borderColor: color }}
    >
      <Icon className="size-4 shrink-0" style={{ color }} aria-hidden />
      <span className="font-mono text-[11px] font-semibold" style={{ color }}>
        HTTP {locked ? '423 Locked' : '429 Too Many Requests'}
      </span>
      <span className="font-medium">
        <span className="font-mono">{latest.sourceKey}</span> {locked ? 'locked' : 'throttled'} by {latest.ruleId}
      </span>
      <span className="hidden truncate text-muted-foreground md:inline">{latest.reason}</span>
      <div className="ml-auto flex shrink-0 items-center gap-3 text-muted-foreground">
        <span className="font-mono">retry in {fmtRemaining(expires - now)}</span>
        {incidentId && (
          <Link href={`/soc?incident=${incidentId}`} className="text-primary hover:underline">
            View incident
          </Link>
        )}
        <button onClick={() => setDismissed(key)} aria-label="Dismiss" className="rounded p-0.5 hover:bg-secondary">
          <X className="size-3.5" />
        </button>
      </div>
    </div>
  );
}

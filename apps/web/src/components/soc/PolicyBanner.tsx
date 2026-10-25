'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Lock, Timer, X, FileWarning } from 'lucide-react';
import { usePolicy } from '@/store/policy';
import { fmtRemaining } from './meta';

const VARIANT = {
  429: { icon: Timer, color: 'hsl(var(--high))', lead: 'Slow down — you are being rate limited.' },
  423: { icon: Lock, color: 'hsl(var(--critical))', lead: 'Access temporarily locked by security policy.' },
  413: { icon: FileWarning, color: 'hsl(var(--medium))', lead: 'Request was too large and was rejected.' },
} as const;

/**
 * Global feedback banner for defensive policy responses. Any api() call that receives
 * 429 / 423 / 413 reports into the policy store; this banner renders it with a live
 * Retry-After countdown and clears itself once the client may retry.
 */
export function PolicyBanner() {
  const { notice, dismiss } = usePolicy();
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!notice?.retryAt) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [notice?.retryAt]);

  useEffect(() => {
    if (notice?.retryAt && now >= notice.retryAt) dismiss();
  }, [now, notice?.retryAt, dismiss]);

  if (!notice) return null;
  const v = VARIANT[notice.status];
  const Icon = v.icon;

  return (
    <div
      role="alert"
      aria-live="assertive"
      className="flex items-center gap-3 border-b px-4 py-2 text-[12px]"
      style={{ background: `color-mix(in srgb, ${v.color} 12%, transparent)`, borderColor: v.color }}
    >
      <Icon className="size-4 shrink-0" style={{ color: v.color }} aria-hidden />
      <span className="font-mono text-[11px] font-semibold" style={{ color: v.color }}>
        HTTP {notice.status}
      </span>
      <span className="font-medium">{v.lead}</span>
      <span className="truncate text-muted-foreground">{notice.detail}</span>
      <div className="ml-auto flex shrink-0 items-center gap-3 text-muted-foreground">
        {notice.retryAt && (
          <span className="font-mono">retry in {fmtRemaining(notice.retryAt - now)}</span>
        )}
        {notice.ruleId && <span className="font-mono">{notice.ruleId}</span>}
        {notice.incidentId && (
          <Link href={`/soc?incident=${notice.incidentId}`} className="text-primary hover:underline">
            View incident
          </Link>
        )}
        <button onClick={dismiss} aria-label="Dismiss" className="rounded p-0.5 hover:bg-secondary">
          <X className="size-3.5" />
        </button>
      </div>
    </div>
  );
}

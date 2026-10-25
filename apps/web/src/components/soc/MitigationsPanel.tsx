'use client';

import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { useReleaseMitigation } from '@/lib/soc/queries';
import type { Mitigation } from '@/types/soc';
import { fmtRemaining, socSeverityColor } from './meta';

export function MitigationsPanel({ items }: { items: Mitigation[] }) {
  const [now, setNow] = useState(() => Date.now());
  const release = useReleaseMitigation();

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  if (!items.length) {
    return <div className="py-6 text-center text-[11.5px] text-muted-foreground">No active mitigations.</div>;
  }

  return (
    <ul className="divide-y">
      {items.map((m) => {
        const locked = m.action === 'LOCK';
        return (
          <li key={m.sourceKey} className="flex items-center gap-3 py-2 text-[11.5px]">
            <span
              className="w-[74px] shrink-0 rounded px-1.5 py-0.5 text-center font-mono text-[10px] font-semibold"
              style={{
                color: socSeverityColor(locked ? 'CRITICAL' : 'HIGH'),
                background: `color-mix(in srgb, ${socSeverityColor(locked ? 'CRITICAL' : 'HIGH')} 15%, transparent)`,
              }}
            >
              {locked ? '423 LOCK' : '429 THROTTLE'}
            </span>
            <div className="min-w-0 flex-1">
              <div className="font-mono">{m.sourceKey}</div>
              <div className="truncate text-[10.5px] text-muted-foreground" title={m.reason}>
                {m.ruleId} · {m.reason}
              </div>
            </div>
            <div className="shrink-0 text-right">
              <div className="font-mono">{fmtRemaining(new Date(m.expiresAt).getTime() - now)}</div>
              <div className="text-[10px] text-muted-foreground">{m.blockedRequests} blocked</div>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-2 text-[11px]"
              disabled={release.isPending}
              onClick={() =>
                release.mutate(m.sourceKey, {
                  onSuccess: () => toast.success(`Released ${m.sourceKey}`),
                  onError: (e) => toast.error(`Release failed: ${e.message}`),
                })
              }
            >
              Release
            </Button>
          </li>
        );
      })}
    </ul>
  );
}

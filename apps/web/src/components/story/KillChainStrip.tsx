'use client';

import { cn } from '@/lib/utils';
import type { StoryEvent, StoryEventKind } from '@/types/domain';

const ORDER: StoryEventKind[] = [
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'lateral-movement',
  'collection',
  'exfiltration',
  'impact',
];

const SHORT: Record<StoryEventKind, string> = {
  'initial-access': 'Init',
  execution: 'Exec',
  persistence: 'Persist',
  'privilege-escalation': 'PrivEsc',
  'lateral-movement': 'Lateral',
  collection: 'Collect',
  exfiltration: 'Exfil',
  impact: 'Impact',
  response: 'Respond',
};

export function KillChainStrip({ events }: { events: StoryEvent[] }) {
  const observed = new Set(events.filter((e) => !e.inferred).map((e) => e.kind));
  const inferred = new Set(events.filter((e) => e.inferred).map((e) => e.kind));

  return (
    <div className="flex items-center gap-1 overflow-x-auto rounded-lg border border-border bg-card p-2">
      {ORDER.map((k, i) => {
        const o = observed.has(k);
        const inf = inferred.has(k);
        return (
          <div key={k} className="flex items-center">
            <div
              className={cn(
                'flex min-w-[86px] flex-col items-center gap-1 rounded-md px-3 py-1.5 text-[11px]',
                o && 'bg-primary/15 text-primary',
                !o && inf && 'border border-dashed border-muted-foreground/60 text-muted-foreground',
                !o && !inf && 'text-muted-foreground/50',
              )}
            >
              <span className="font-medium">{SHORT[k]}</span>
              <span className="text-[9.5px] uppercase tracking-wide">
                {o ? 'observed' : inf ? 'inferred' : 'none'}
              </span>
            </div>
            {i < ORDER.length - 1 && <span className="px-1 text-muted-foreground/40">›</span>}
          </div>
        );
      })}
    </div>
  );
}
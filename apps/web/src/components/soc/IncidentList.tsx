'use client';

import { cn } from '@/lib/utils';
import type { SocIncident } from '@/types/soc';
import { fmtTime, socSeverityColor } from './meta';

export function IncidentList({
  items,
  selectedId,
  onSelect,
}: {
  items: SocIncident[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (!items.length) {
    return <div className="py-6 text-center text-[11.5px] text-muted-foreground">No incidents yet.</div>;
  }
  return (
    <ul className="divide-y" role="listbox" aria-label="Incidents">
      {items.map((inc) => (
        <li key={inc.id}>
          <button
            role="option"
            aria-selected={inc.id === selectedId}
            onClick={() => onSelect(inc.id)}
            className={cn(
              'flex w-full items-center gap-2.5 px-2 py-2 text-left text-[11.5px] hover:bg-secondary/40',
              inc.id === selectedId && 'bg-primary/10',
            )}
          >
            <span className="size-2 shrink-0 rounded-full" style={{ background: socSeverityColor(inc.severity) }} aria-hidden />
            <span className="w-[56px] shrink-0 text-[10px] font-semibold" style={{ color: socSeverityColor(inc.severity) }}>
              {inc.severity}
            </span>
            <span className="min-w-0 flex-1 truncate">{inc.title}</span>
            <span className="shrink-0 font-mono text-[10.5px] text-muted-foreground">{inc.sourceKey}</span>
            <span
              className={cn(
                'w-[70px] shrink-0 text-right text-[10px] uppercase tracking-wide',
                inc.status === 'RESOLVED' ? 'text-muted-foreground' : 'text-foreground',
              )}
            >
              {inc.status === 'RESOLVED' ? 'resolved' : inc.stage.toLowerCase()}
            </span>
            <span className="w-[76px] shrink-0 whitespace-nowrap text-right font-mono text-[10px] text-muted-foreground">
              {fmtTime(inc.updatedAt)}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}

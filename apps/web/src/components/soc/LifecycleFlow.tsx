'use client';

import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { LifecycleStage, SocIncident } from '@/types/soc';
import { STAGES, STAGE_INDEX, fmtTime, socSeverityColor } from './meta';

interface Props {
  counts: Partial<Record<LifecycleStage | 'RESOLVED', number>>;
  /** Funnel: incidents in the retention window that reached each stage. */
  /** Stage that most recently received an event, for a brief highlight. */
  pulse: LifecycleStage | null;
  incident: SocIncident | null;
}

/**
 * Incident response lifecycle: Event Ingestion -> Anomaly Detection -> Policy Enforcement -> Mitigation.
 * Top: funnel of how many incidents reached each stage. Bottom: the selected incident's path through it.
 */
export function LifecycleFlow({ counts, pulse, incident }: Props) {
  const reached = incident ? STAGE_INDEX[incident.stage] : -1;

  return (
    <div>
      <ol className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4" aria-label="Incident response lifecycle">
        {STAGES.map((s, i) => {
          const Icon = s.icon;
          const active = incident ? i <= reached : false;
          return (
            <li key={s.key} className="relative flex items-center">
              <div
                className={cn(
                  'flex w-full items-center gap-3 rounded-lg border px-3 py-2.5 transition-colors',
                  pulse === s.key && 'ring-2 ring-primary/60',
                  active ? 'border-primary/50 bg-primary/10' : 'bg-secondary/30',
                )}
              >
                <div
                  className={cn(
                    'flex size-8 shrink-0 items-center justify-center rounded-md',
                    active ? 'bg-primary/20 text-primary' : 'bg-secondary text-muted-foreground',
                  )}
                >
                  <Icon className="size-4" aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-[12px] font-medium">{s.label}</div>
                  <div className="truncate text-[10.5px] text-muted-foreground">{s.hint}</div>
                </div>
                <div className="text-right">
                  <div className="font-mono text-[18px] leading-none">{counts[s.key] ?? 0}</div>
                  <div className="text-[9.5px] uppercase tracking-wide text-muted-foreground">reached</div>
                </div>
              </div>
              {i < STAGES.length - 1 && (
                <ChevronRight
                  className="absolute -right-2.5 z-10 hidden size-4 text-muted-foreground/60 lg:block"
                  aria-hidden
                />
              )}
            </li>
          );
        })}
      </ol>

      <div className="mt-2 text-[10.5px] text-muted-foreground">
        Incidents reaching each stage · {counts.RESOLVED ?? 0} resolved in retention window
      </div>
    </div>
  );
}

export function IncidentTimeline({ incident }: { incident: SocIncident | null }) {
  if (!incident) {
    return (
      <div className="flex h-full min-h-[120px] items-center justify-center rounded-md border border-dashed px-3 text-center text-[11.5px] text-muted-foreground">
        Select an incident to trace its lifecycle.
      </div>
    );
  }
  return (
    <div className="rounded-md border p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[12px]">
        <span
          className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
          style={{ color: socSeverityColor(incident.severity), background: `color-mix(in srgb, ${socSeverityColor(incident.severity)} 15%, transparent)` }}
        >
          {incident.severity}
        </span>
        <span className="font-medium">{incident.title}</span>
        <span className="font-mono text-muted-foreground">{incident.sourceKey}</span>
        <span className="ml-auto text-[10.5px] text-muted-foreground">
          {incident.status} · {incident.blockedRequests} blocked
        </span>
      </div>
      <ol className="relative ml-1.5 border-l pl-4">
        {incident.steps.map((step, i) => (
          <li key={`${step.at}-${i}`} className="relative pb-2 last:pb-0">
            <span
              className="absolute -left-[21px] top-1 size-2.5 rounded-full border-2 border-card"
              style={{ background: 'hsl(var(--primary))' }}
              aria-hidden
            />
            <div className="flex flex-wrap items-baseline gap-x-2 text-[11.5px]">
              <span className="w-[64px] shrink-0 font-mono text-[10.5px] text-muted-foreground">{fmtTime(step.at)}</span>
              <span className="w-[78px] shrink-0 text-[10.5px] font-semibold uppercase tracking-wide">{step.stage}</span>
              <span className="text-muted-foreground">{step.detail}</span>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

'use client';

import { AlertTriangle, Server, Wrench } from 'lucide-react';
import type { BlastRadius } from '@/types/domain';

export function BlastRadiusPreview({ blastRadius }: { blastRadius: BlastRadius }) {
  return (
    <div className="rounded-lg border border-border bg-secondary/40 p-3">
      <div className="mb-2 flex items-center gap-2 text-[11.5px] text-muted-foreground">
        <AlertTriangle className="size-3.5 text-[hsl(var(--medium))]" />
        Blast radius
      </div>

      <div className="grid grid-cols-2 gap-3 text-[12px]">
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-muted-foreground">
            <Server className="size-3" /> Nodes affected
          </div>
          <div className="flex flex-wrap gap-1">
            {(blastRadius?.nodeIds ?? []).map((n) => (
              <span
                key={n}
                className="rounded bg-background px-1.5 py-0.5 font-mono text-[10.5px]"
              >
                {n}
              </span>
            ))}
          </div>
        </div>
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-muted-foreground">
            <Wrench className="size-3" /> Services
          </div>
          <div className="flex flex-wrap gap-1">
            {(blastRadius?.servicesAffected ?? []).length === 0 ? (
              <span className="text-muted-foreground">None</span>
            ) : (
              blastRadius.servicesAffected.map((s) => (
                <span
                  key={s}
                  className="rounded bg-background px-1.5 py-0.5 text-[10.5px]"
                >
                  {s}
                </span>
              ))
            )}
          </div>
        </div>
      </div>

      {blastRadius.estimatedDowntime && (
        <div className="mt-2 text-[11.5px] text-muted-foreground">
          Estimated downtime: <span className="text-foreground">{blastRadius.estimatedDowntime}</span>
        </div>
      )}
    </div>
  );
}
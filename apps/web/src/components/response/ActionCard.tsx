'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import type { ResponseAction } from '@/types/domain';
import { ApprovalDialog } from './ApprovalDialog';
import { CheckCircle2, Clock, XCircle, Zap } from 'lucide-react';
import Link from 'next/link';
import { useSim } from '@/lib/sim/runtime';

const STATE_STYLE: Record<ResponseAction['state'], string> = {
  proposed: 'bg-[hsl(var(--medium))]/15 text-[hsl(var(--medium))] border-[hsl(var(--medium))]/30',
  approved: 'bg-primary/15 text-primary border-primary/30',
  executing: 'bg-primary/15 text-primary border-primary/30',
  done: 'bg-[hsl(var(--low))]/15 text-[hsl(var(--low))] border-[hsl(var(--low))]/30',
  failed: 'bg-[hsl(var(--critical))]/15 text-[hsl(var(--critical))] border-[hsl(var(--critical))]/30',
  rejected: 'bg-secondary text-muted-foreground border-border',
};

export function ActionCard({ action }: { action: ResponseAction }) {
  const [open, setOpen] = useState(false);
  const incident = useSim((s) => s.state?.incidents.find((i) => i.id === action.incidentId));

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-4 rounded-lg border border-border bg-card p-4">
        <div className="min-w-0">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <Zap className="size-3.5 text-muted-foreground" />
            <span className="font-mono text-[12.5px]">{action.kind}</span>
            <span className="text-muted-foreground">→</span>
            <span className="font-mono text-[12.5px]">{action.target}</span>
            <Badge variant="outline" className={`ml-1 text-[10px] ${STATE_STYLE[action.state]}`}>
              {action.state}
            </Badge>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-muted-foreground">
            <Link href={`/incidents/${action.incidentId}`} className="flex items-center gap-1 hover:text-foreground hover:underline">
              <Clock className="size-3" />
              {incident ? `${incident.title} · ${incident.sourceKey}` : `incident ${action.incidentId}`}
            </Link>
            {!action.requiresApproval && <span>automatic</span>}
            {action.riskReduction !== undefined && (
              <span className="text-[hsl(var(--low))]">
                −{action.riskReduction} risk pts
              </span>
            )}
          </div>
        </div>
        {action.state === 'proposed' ? (
          <Button size="sm" variant="destructive" onClick={() => setOpen(true)}>
            Review & approve
          </Button>
        ) : action.state === 'done' ? (
          <CheckCircle2 className="size-4 text-[hsl(var(--low))]" />
        ) : action.state === 'rejected' ? (
          <XCircle className="size-4 text-muted-foreground" />
        ) : null}
      </div>

      {action.state === 'proposed' && (
        <ApprovalDialog action={action} open={open} onOpenChange={setOpen} />
      )}
    </>
  );
}
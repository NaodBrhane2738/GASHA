'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Crown, ShieldAlert } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { NodeKind, Exposure } from '@/types/domain';
import { KIND_ICON, riskColor } from '@/lib/graph/nodeMeta';

export interface TwinNodeData {
  label: string;
  kind: NodeKind;
  provider: string;
  exposure: Exposure;
  riskScore: number;
  criticality: number;
  isCrownJewel?: boolean;
  dimmed?: boolean;
  onPath?: boolean;
  selected?: boolean;
  [key: string]: unknown;
}

export function TwinNode({ data }: NodeProps) {
  const d = data as TwinNodeData;
  const Icon = KIND_ICON[d.kind];
  const rc = riskColor(d.riskScore);

  return (
    <div
      className={cn(
        'group relative w-[220px] rounded-lg border bg-card p-3 shadow-sm transition-all',
        d.onPath ? 'border-[hsl(var(--critical))] ring-2 ring-[hsl(var(--critical))]/40' : 'border-border',
        d.dimmed && 'opacity-20',
        d.selected && 'ring-2 ring-primary',
      )}
    >
      <Handle type="target" position={Position.Left} className="!bg-border !size-1.5" />
      <Handle type="source" position={Position.Right} className="!bg-border !size-1.5" />

      <div className="flex items-center gap-2">
        <div className="flex size-7 shrink-0 items-center justify-center rounded-md bg-secondary">
          <Icon className="size-3.5 text-muted-foreground" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-medium">{d.label}</div>
          <div className="truncate text-[10.5px] uppercase tracking-wide text-muted-foreground">
            {d.provider} · {d.exposure}
          </div>
        </div>
        {d.isCrownJewel && (
          <Crown className="size-3.5 shrink-0 text-[hsl(var(--medium))]" />
        )}
      </div>

      <div className="mt-2.5">
        <div className="mb-1 flex items-center justify-between text-[10px] text-muted-foreground">
          <span>Risk</span>
          <span className="font-mono" style={{ color: rc }}>
            {d.riskScore}
          </span>
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-secondary">
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${d.riskScore}%`, background: rc }}
          />
        </div>
      </div>

      {d.exposure === 'public' && (
        <div className="mt-2 flex items-center gap-1 text-[10px] text-[hsl(var(--high))]">
          <ShieldAlert className="size-3" /> Public exposure
        </div>
      )}
    </div>
  );
}
'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import { ShieldCheck, ShieldAlert } from 'lucide-react';
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
  isAttacked?: boolean;
  isSecured?: boolean;
  attackTechnique?: string;
  attackSeverity?: string;
  attackSummary?: string;
  attackCount?: number;
  [key: string]: unknown;
}

export function TwinNode({ data }: NodeProps) {
  const d = data as TwinNodeData;
  const Icon = KIND_ICON[d.kind];
  const isAttacked = !!d.isAttacked;
  const isSecured = !!d.isSecured && !isAttacked;
  const effectiveRisk = isAttacked ? 99 : isSecured ? 15 : d.riskScore;
  const rc = isAttacked ? 'hsl(var(--critical))' : isSecured ? 'hsl(var(--primary))' : riskColor(effectiveRisk);

  return (
    <div
      className={cn(
        'group relative w-[230px] rounded-lg border bg-card p-3 shadow-sm transition-colors',
        isAttacked
          ? 'border-border bg-card'
          : isSecured
          ? 'border-border bg-card'
          : d.onPath
          ? 'border-primary'
          : 'border-border',
        d.dimmed && !isAttacked && !isSecured && 'opacity-20',
        d.selected && 'ring-1 ring-primary',
      )}
    >
      {/* Static Threat or Secured Pill Badge */}
      {isAttacked && (
        <div className="mb-2 flex items-center justify-between rounded bg-secondary border border-border px-2 py-0.5 text-[10px] font-semibold text-foreground">
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full bg-primary" />
            <span className="tracking-wide text-foreground font-bold">UNDER ATTACK</span>
          </div>
          <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">
            {d.attackTechnique || 'INCURSION'}
          </span>
        </div>
      )}

      {isSecured && (
        <div className="mb-2 flex items-center justify-between rounded bg-secondary border border-border px-2 py-0.5 text-[9.5px] font-semibold text-foreground">
          <div className="flex items-center gap-1.5 font-mono">
            <ShieldCheck className="size-3 text-primary" />
            <span>PROTECTED & NOMINAL</span>
          </div>
          <span className="font-mono text-[9px] text-muted-foreground">CONTAINED</span>
        </div>
      )}

      <Handle type="target" position={Position.Left} className="!bg-border !size-1.5" />
      <Handle type="source" position={Position.Right} className="!bg-border !size-1.5" />

      <div className="flex items-center gap-2">
        <div
          className={cn(
            'flex size-7 shrink-0 items-center justify-center rounded-md transition-colors',
            isAttacked
              ? 'bg-secondary text-foreground'
              : isSecured
              ? 'bg-secondary text-primary'
              : 'bg-secondary text-muted-foreground',
          )}
        >
          {isAttacked ? (
            <ShieldAlert className="size-3.5 text-foreground" />
          ) : isSecured ? (
            <ShieldCheck className="size-3.5 text-primary" />
          ) : (
            <Icon className="size-3.5" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[12.5px] font-medium text-foreground">
            {d.label}
          </div>
          <div className="truncate text-[10.5px] uppercase tracking-wide text-muted-foreground">
            {d.provider} · {d.exposure}
          </div>
        </div>
        {d.isCrownJewel && (
          <span className="text-[9px] font-mono px-1 rounded bg-secondary text-muted-foreground uppercase">
            Core
          </span>
        )}
      </div>

      <div className="mt-2.5">
        <div className="mb-1 flex items-center justify-between text-[10px] text-muted-foreground">
          <span className="font-mono text-muted-foreground flex items-center gap-1">
            {isAttacked ? 'Threat Level' : isSecured ? 'Secured Risk' : 'Risk'}
          </span>
          <span className="font-mono font-bold text-foreground">
            {effectiveRisk}
          </span>
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-secondary">
          <div
            className="h-full rounded-full transition-all"
            style={{ width: `${effectiveRisk}%`, background: rc }}
          />
        </div>
      </div>

      {isAttacked ? (
        <div className="mt-2 flex items-center gap-1 text-[10px] font-medium text-muted-foreground">
          <ShieldAlert className="size-3 shrink-0 text-foreground" />
          <span className="truncate">{d.attackSummary || 'Active telemetry indicates target incursion'}</span>
        </div>
      ) : isSecured ? (
        <div className="mt-2 flex items-center gap-1 text-[10px] text-muted-foreground font-mono">
          <ShieldCheck className="size-3 shrink-0 text-primary" />
          <span>Threat blocked · Zero active incursions</span>
        </div>
      ) : (
        d.exposure === 'public' && (
          <div className="mt-2 flex items-center gap-1 text-[10px] text-muted-foreground">
            <ShieldAlert className="size-3" /> Public exposure
          </div>
        )
      )}
    </div>
  );
}

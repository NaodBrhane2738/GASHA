'use client';

import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Crown, ShieldAlert, AlertTriangle, Zap, Flame, ShieldCheck } from 'lucide-react';
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
  const rc = isAttacked ? '#ef4444' : riskColor(d.riskScore);

  return (
    <div
      className={cn(
        'group relative w-[230px] rounded-lg border bg-card p-3 shadow-sm transition-all',
        isAttacked
          ? 'threat-node-active bg-gradient-to-b from-red-950/40 via-card to-card ring-2 ring-red-500/70'
          : d.onPath
          ? 'border-[hsl(var(--critical))] ring-2 ring-[hsl(var(--critical))]/40'
          : 'border-border',
        d.dimmed && !isAttacked && 'opacity-20',
        d.selected && !isAttacked && 'ring-2 ring-primary',
      )}
    >
      {/* Outer Radar Waves & Glow when under attack */}
      {isAttacked && (
        <>
          <span className="pointer-events-none absolute -inset-2.5 rounded-xl border border-red-500/70 bg-red-500/10 threat-radar-wave" />
          <span className="pointer-events-none absolute -inset-1 rounded-xl bg-red-500/20 blur-sm animate-pulse" />
        </>
      )}

      {/* Floating Active Threat Pill Badge */}
      {isAttacked && (
        <div className="mb-2 flex items-center justify-between rounded bg-red-500/20 border border-red-500/50 px-2 py-0.5 text-[10px] font-semibold text-red-400">
          <div className="flex items-center gap-1.5">
            <span className="relative flex size-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
              <span className="relative inline-flex size-2 rounded-full bg-red-500" />
            </span>
            <span className="tracking-wide text-red-300 font-bold">UNDER ATTACK</span>
          </div>
          <span className="font-mono text-[9px] uppercase tracking-wider text-red-300">
            {d.attackTechnique || 'INCURSION'}
          </span>
        </div>
      )}

      <Handle type="target" position={Position.Left} className="!bg-border !size-1.5" />
      <Handle type="source" position={Position.Right} className="!bg-border !size-1.5" />

      <div className="flex items-center gap-2">
        <div
          className={cn(
            'flex size-7 shrink-0 items-center justify-center rounded-md transition-colors',
            isAttacked ? 'bg-red-500/20 text-red-400 shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 'bg-secondary text-muted-foreground',
          )}
        >
          {isAttacked ? (
            <Zap className="size-3.5 text-red-500 animate-bounce" />
          ) : (
            <Icon className="size-3.5" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className={cn('truncate text-[12.5px] font-medium', isAttacked && 'text-red-200 font-semibold')}>
            {d.label}
          </div>
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
          <span className={cn(isAttacked && 'font-semibold text-red-400 flex items-center gap-1')}>
            {isAttacked ? (
              <>
                <Flame className="size-3 text-red-500 animate-pulse" /> Threat Surge
              </>
            ) : (
              'Risk'
            )}
          </span>
          <span className="font-mono font-bold" style={{ color: rc }}>
            {isAttacked ? 99 : d.riskScore}
          </span>
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-secondary">
          <div
            className={cn(
              'h-full rounded-full transition-all',
              isAttacked && 'bg-red-500 animate-pulse',
            )}
            style={{ width: `${isAttacked ? 99 : d.riskScore}%`, background: rc }}
          />
        </div>
      </div>

      {isAttacked ? (
        <div className="mt-2 flex items-center gap-1 text-[10px] font-medium text-red-400">
          <AlertTriangle className="size-3 shrink-0 text-red-500 animate-pulse" />
          <span className="truncate">{d.attackSummary || 'Active telemetry indicates target incursion'}</span>
        </div>
      ) : (
        d.exposure === 'public' && (
          <div className="mt-2 flex items-center gap-1 text-[10px] text-[hsl(var(--high))]">
            <ShieldAlert className="size-3" /> Public exposure
          </div>
        )
      )}
    </div>
  );
}

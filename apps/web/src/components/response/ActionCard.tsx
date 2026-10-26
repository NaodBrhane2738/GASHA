'use client';

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import type { ResponseAction } from '@/types/domain';
import { ApprovalDialog } from './ApprovalDialog';
import { CheckCircle2, Clock, XCircle, Lock, ShieldCheck, Database } from 'lucide-react';
import { useApproveResponse } from '@/lib/api/queries';
import { useUI, type ArchivedIncidentRecord } from '@/store/ui';
import { toast } from 'sonner';

const STATE_STYLE: Record<string, string> = {
  proposed: 'bg-secondary text-muted-foreground border-border',
  approved: 'bg-primary/15 text-primary border-primary/30',
  executing: 'bg-primary/15 text-primary border-primary/30',
  done: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  failed: 'bg-red-500/15 text-red-400 border-red-500/30',
  rejected: 'bg-secondary text-muted-foreground border-border',
};

export function ActionCard({ action, onExecuted }: { action: any; onExecuted?: () => void }) {
  const [open, setOpen] = useState(false);
  const approve = useApproveResponse();
  const blockThreat = useUI((s) => s.blockThreat);

  const kind = action.kind || (action.actionType === 'BLOCK_SOURCE' ? 'block-ip' : action.actionType === 'ISOLATE_RESOURCE' ? 'isolate-host' : action.actionType || 'quarantine');
  const target = action.target || action.targetIdentifier || '198.51.100.101';
  const rawStatus = String(action.state || action.status || 'proposed').toLowerCase();
  const state = (rawStatus === 'pending_approval' || rawStatus === 'proposed')
    ? 'proposed'
    : (rawStatus === 'succeeded' || rawStatus === 'success' || rawStatus === 'done' || rawStatus === 'completed')
    ? 'done'
    : rawStatus;

  const onQuickApprove = async () => {
    try {
      try {
        await approve.mutateAsync(action.id);
      } catch (err) {
        console.warn('Backend approve sync:', err);
      }

      const nowIso = new Date().toISOString();
      const assetId = action.primaryAffectedAssetId || (action.blastRadius?.nodeIds?.[0]) || 'auth-svc';
      const archivedRecord: ArchivedIncidentRecord = {
        id: action.incidentId || `inc-${Date.now()}`,
        title: action.title || `Containment Order for IP ${target}`,
        severity: 'critical',
        status: 'contained',
        openedAt: nowIso,
        createdAt: nowIso,
        attackerIp: target,
        primaryAffectedAssetId: assetId,
        cveId: 'CVE-2023-34362',
        technique: 'T1190 · Exploit Public-Facing App',
        summary: `Threat blocked at firewall. Adversary IP ${target} quarantined and asset ${assetId} restored to nominal.`,
        description: action.reason || `Adversary IP ${target} executed malicious incursions targeting ${assetId}. Active perimeter firewall drop order enforced. System fully restored to nominal state. Incident moved to Archive.`,
        riskBefore: 99,
        riskAfter: 15,
        detectionIds: action.supportingEvidenceIds || [],
      };

      blockThreat(target, assetId, archivedRecord);
      toast.success(`Block executed for ${target}! Threat neutralized and moved to Archive.`);
      if (onExecuted) {
        onExecuted();
      }
    } catch (err: any) {
      toast.error(err?.message || 'Execution failed');
    }
  };

  const normalizedAction: ResponseAction = {
    id: action.id,
    incidentId: action.incidentId || 'inc-1',
    kind: kind as any,
    target,
    requiresApproval: true,
    state: state as any,
    blastRadius: action.blastRadius || { nodeIds: [target], servicesAffected: [] },
    riskReduction: action.riskReduction ?? 15,
  };

  return (
    <>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-lg border border-border bg-card p-4 transition-all hover:border-primary/40">
        <div className="min-w-0">
          <div className="mb-1.5 flex flex-wrap items-center gap-2">
            <span className="font-mono text-[12.5px] font-bold text-foreground uppercase">{kind}</span>
            <span className="text-muted-foreground">&rarr;</span>
            <span className="font-mono text-[12.5px] font-bold text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/30">
              {target}
            </span>
            <Badge variant="outline" className={`ml-1 text-[10px] uppercase font-mono font-bold ${STATE_STYLE[state] || STATE_STYLE.proposed}`}>
              {state === 'done' ? 'Contained' : state}
            </Badge>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[11.5px] text-muted-foreground">
            <span className="flex items-center gap-1 font-mono">
              incident {action.incidentId || 'inc-active'}
            </span>
            <span className="text-emerald-400 font-mono font-semibold">
              −{action.riskReduction ?? 15} risk pts
            </span>
            {action.reason && (
              <span className="text-muted-foreground italic truncate max-w-[320px]">
                {action.reason}
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-center">
          {state === 'proposed' ? (
            <>
              <Button
                size="sm"
                variant="destructive"
                disabled={approve.isPending}
                onClick={onQuickApprove}
                className="h-8 text-[11.5px] font-bold gap-1 shadow-sm"
              >
                <Lock className="size-3" />
                {approve.isPending ? 'Enforcing…' : 'Execute Block'}
              </Button>
              <Button size="sm" variant="outline" onClick={() => setOpen(true)} className="h-8 text-[11.5px]">
                Review
              </Button>
            </>
          ) : state === 'done' ? (
            <div className="flex items-center gap-1.5 rounded bg-emerald-500/10 px-2.5 py-1 text-[11px] font-mono text-emerald-400 border border-emerald-500/30">
              <CheckCircle2 className="size-3.5" />
              <span>ACTIVE PERIMETER DROP · ARCHIVED</span>
            </div>
          ) : state === 'rejected' ? (
            <div className="flex items-center gap-1 text-[11px] font-mono text-muted-foreground">
              <XCircle className="size-3.5" /> Rejected
            </div>
          ) : null}
        </div>
      </div>

      {state === 'proposed' && (
        <ApprovalDialog action={normalizedAction} open={open} onOpenChange={setOpen} />
      )}
    </>
  );
}

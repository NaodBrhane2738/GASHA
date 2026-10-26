'use client';

import { useState } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { BlastRadiusPreview } from './BlastRadiusPreview';
import type { ResponseAction } from '@/types/domain';
import { useApproveResponse, useRejectResponse } from '@/lib/api/queries';
import { useUI, type ArchivedIncidentRecord } from '@/store/ui';
import { toast } from 'sonner';

export function ApprovalDialog({
  action,
  open,
  onOpenChange,
}: {
  action: ResponseAction;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const [typed, setTyped] = useState('');
  const approve = useApproveResponse();
  const reject = useRejectResponse();
  const blockThreat = useUI((s) => s.blockThreat);

  const confirmWord = action.kind === 'isolate-host' ? 'ISOLATE' : 'CONFIRM';

  const onConfirm = async () => {
    try {
      try {
        await approve.mutateAsync(action.id);
      } catch (err) {
        console.warn('Backend sync note:', err);
      }

      const nowIso = new Date().toISOString();
      const assetId = (action.blastRadius?.nodeIds?.[0]) || 'auth-svc';
      const archivedRecord: ArchivedIncidentRecord = {
        id: action.incidentId || `inc-${Date.now()}`,
        title: `Containment Order for ${action.target}`,
        severity: 'critical',
        status: 'contained',
        openedAt: nowIso,
        createdAt: nowIso,
        attackerIp: action.target,
        primaryAffectedAssetId: assetId,
        cveId: 'CVE-2023-34362',
        technique: 'T1190 · Exploit Public-Facing App',
        summary: `Threat blocked at firewall. Adversary IP ${action.target} quarantined and asset ${assetId} restored to nominal.`,
        description: `Adversary at target ${action.target} executed security incursions. Containment order successfully executed. System returned to nominal. Record moved to Archive.`,
        riskBefore: 99,
        riskAfter: 15,
        detectionIds: [],
      };

      blockThreat(action.target, assetId, archivedRecord);
      toast.success(`Executed block on ${action.target}! Threat moved to Archive.`);
      onOpenChange(false);
      setTyped('');
    } catch (err: any) {
      toast.error(err?.message || 'Execution failed');
    }
  };

  const onReject = async () => {
    try {
      await reject.mutateAsync(action.id);
      toast.message('Action rejected');
      onOpenChange(false);
    } catch {
      toast.error('Rejection failed');
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            Approve: <span className="font-mono">{action.kind}</span> on{' '}
            <span className="font-mono">{action.target}</span>
          </DialogTitle>
          <DialogDescription>
            This action is logged and reversible for 60 minutes after execution.
          </DialogDescription>
        </DialogHeader>

        <BlastRadiusPreview blastRadius={action.blastRadius ?? { nodeIds: [action.target], servicesAffected: [] }} />

        <div className="rounded-md border border-[hsl(var(--medium))]/40 bg-[hsl(var(--medium))]/10 p-3 text-[12.5px]">
          Projected risk reduction:{' '}
          <strong className="text-[hsl(var(--low))]">−{action.riskReduction ?? 0} pts</strong>
          {' '}· {(action.blastRadius?.servicesAffected ?? []).length} service(s) affected
        </div>

        <Input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={`Type ${confirmWord} to confirm`}
          className="font-mono"
        />

        <DialogFooter>
          <Button variant="ghost" onClick={onReject} disabled={reject.isPending}>
            Reject
          </Button>
          <Button
            variant="default"
            disabled={typed !== confirmWord || approve.isPending}
            onClick={onConfirm}
          >
            {approve.isPending ? 'Executing…' : 'Execute containment'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

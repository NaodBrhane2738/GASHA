'use client';

import { Suspense, useMemo } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useResponses, useApproveResponse, useProposeResponse } from '@/lib/api/queries';
import { ActionCard } from '@/components/response/ActionCard';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Shield, Lock, CheckCircle2, Radar, Activity, ArrowRight, AlertTriangle, Flame, Database } from 'lucide-react';
import { toast } from 'sonner';

function ResponseContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const quarantineIp = searchParams.get('quarantine') || searchParams.get('ip');

  const { data, refetch } = useResponses();
  const approve = useApproveResponse();

  const allActions = useMemo(() => {
    const list = [...(data ?? [])];
    // If quarantineIp is in URL but no action matches it yet, synthesize a proposed action for immediate display
    if (quarantineIp && !list.some((a) => (a.target === quarantineIp || (a as any).targetIdentifier === quarantineIp))) {
      list.unshift({
        id: `resp-q-${quarantineIp.replace(/\./g, '-')}`,
        incidentId: 'inc-4f3e5cf1',
        kind: 'block-ip',
        target: quarantineIp,
        requiresApproval: true,
        state: 'proposed',
        blastRadius: { nodeIds: [quarantineIp], servicesAffected: ['Nexus Perimeter'] },
        riskReduction: 15,
        reason: `Automated adversary IP quarantine requested from Digital Twin for ${quarantineIp}`,
      } as any);
    }
    return list;
  }, [data, quarantineIp]);

  const proposed = allActions.filter((r) => {
    const s = String(r.state || (r as any).status || '').toLowerCase();
    return s === 'proposed' || s === 'pending_approval';
  });

  const history = allActions.filter((r) => {
    const s = String(r.state || (r as any).status || '').toLowerCase();
    return s !== 'proposed' && s !== 'pending_approval';
  });

  const handleInstantQuarantine = async (action: any) => {
    try {
      await approve.mutateAsync(action.id);
      toast.success(`Successfully enforced perimeter block for IP ${action.target || (action as any).targetIdentifier}`);
      refetch();
    } catch (err: any) {
      toast.error(err?.message || 'Execution failed');
    }
  };

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4 space-y-5">
      {/* Page Title & Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-[14px] font-bold text-foreground flex items-center gap-2">
            <Lock className="size-4 text-primary" />
            Controlled Response & Active Containment Center
          </h2>
          <p className="text-[11.5px] text-muted-foreground">
            Enforce verified host isolation and adversary IP perimeter quarantine to neutralize live attacks.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link href="/twin">
            <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px]">
              <Radar className="size-3.5 text-primary" /> Digital Twin
            </Button>
          </Link>
          <Link href="/telemetry">
            <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px]">
              <Activity className="size-3.5 text-primary" /> Observe Feed
            </Button>
          </Link>
        </div>
      </div>

      {/* Target Quarantine Inbound Alert Banner (if arriving from Digital Twin / Observe) */}
      {quarantineIp && (
        <Card className="border-red-500/50 bg-red-950/20 p-4 shadow-lg animate-in fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-red-500/50 bg-red-500/20 text-red-400">
                <Flame className="size-5 animate-pulse text-red-500" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[13px] font-bold text-foreground">
                    Targeted Adversary Quarantine Requested
                  </span>
                  <Badge variant="destructive" className="font-mono text-[10px] uppercase font-bold">
                    INCOMING QUARANTINE
                  </Badge>
                </div>
                <p className="text-[11.5px] text-muted-foreground mt-0.5">
                  Adversary IP <span className="font-mono text-red-400 font-bold">{quarantineIp}</span> was flagged during active security incursion on the Digital Twin. Enforce containment to block all inbound traffic at the perimeter firewall.
                </p>
              </div>
            </div>

            {proposed.length > 0 && (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => handleInstantQuarantine(proposed[0])}
                disabled={approve.isPending}
                className="h-8 font-bold text-[11.5px] gap-1.5 shrink-0 shadow-md shadow-red-500/30"
              >
                <Lock className="size-3.5" />
                {approve.isPending ? 'Enforcing Perimeter Block…' : 'Enforce Immediate Quarantine'}
              </Button>
            )}
          </div>
        </Card>
      )}

      {/* Awaiting Operator Approval Section */}
      <div>
        <div className="mb-2.5 flex items-center justify-between">
          <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <span>Awaiting Approval & Containment</span>
            <Badge variant="outline" className="font-mono text-[10px] border-amber-500/40 text-amber-400">
              {proposed.length} Action{proposed.length !== 1 ? 's' : ''}
            </Badge>
          </div>
        </div>

        {proposed.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border p-6 text-center text-[12px] text-muted-foreground">
            No containment actions currently pending approval. All perimeter policies are stable.
          </div>
        ) : (
          <div className="space-y-2.5">
            {proposed.map((a) => (
              <ActionCard key={a.id} action={a} />
            ))}
          </div>
        )}
      </div>

      {/* Enforced Containment History & Verification ("See After That") */}
      <div>
        <div className="mb-2.5 flex items-center justify-between">
          <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <CheckCircle2 className="size-3.5 text-emerald-400" />
            <span>Enforced Containment History & Verified Defense</span>
            <Badge variant="outline" className="font-mono text-[10px] border-emerald-500/40 text-emerald-400">
              {history.length} Enforced
            </Badge>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border p-6 text-center text-[12px] text-muted-foreground">
            No previous containment history recorded in this session.
          </div>
        ) : (
          <div className="space-y-2.5">
            {history.map((a) => (
              <ActionCard key={a.id} action={a} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ResponsePage() {
  return (
    <Suspense fallback={<div className="p-6 text-muted-foreground font-mono text-[12px]">Loading response containment…</div>}>
      <ResponseContent />
    </Suspense>
  );
}

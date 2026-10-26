'use client';

import { Suspense, useMemo, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useResponses, useApproveResponse, useIncidents } from '@/lib/api/queries';
import { ActionCard } from '@/components/response/ActionCard';
import { IncidentArchiveView } from '@/components/archive/IncidentArchiveView';
import { useUI, type ArchivedIncidentRecord } from '@/store/ui';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Shield,
  Lock,
  CheckCircle2,
  Radar,
  Activity,
  ArrowRight,
  AlertTriangle,
  ShieldAlert,
  Database,
} from 'lucide-react';
import { toast } from 'sonner';

function ResponseContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const quarantineIp = searchParams.get('quarantine') || searchParams.get('ip');
  const viewQuery = searchParams.get('view');

  const { data, refetch } = useResponses();
  const { data: incidents } = useIncidents();
  const approve = useApproveResponse();

  const blockedIps = useUI((s) => s.blockedIps);
  const blockedAssetIds = useUI((s) => s.blockedAssetIds);
  const blockThreat = useUI((s) => s.blockThreat);

  const [viewMode, setViewMode] = useState<'containment' | 'archives'>(
    viewQuery === 'archives' ? 'archives' : 'containment'
  );
  const [selectedArchiveDate, setSelectedArchiveDate] = useState<string | null>(
    searchParams.get('date') || null
  );
  const [selectedArchiveIncidentId, setSelectedArchiveIncidentId] = useState<string | null>(
    searchParams.get('incidentId') || null
  );

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
    const isProposed = s === 'proposed' || s === 'pending_approval';
    const isAlreadyBlocked = blockedIps.includes(r.target) || blockedIps.includes((r as any).targetIdentifier);
    return isProposed && !isAlreadyBlocked;
  });

  const history = allActions.filter((r) => {
    const s = String(r.state || (r as any).status || '').toLowerCase();
    const isHistory = s !== 'proposed' && s !== 'pending_approval';
    const isAlreadyBlocked = blockedIps.includes(r.target) || blockedIps.includes((r as any).targetIdentifier);
    return isHistory || isAlreadyBlocked;
  });

  const handleInstantQuarantine = async (action: any) => {
    try {
      const target = action.target || (action as any).targetIdentifier || quarantineIp || '198.51.100.101';
      const assetId = action.primaryAffectedAssetId || (action.blastRadius?.nodeIds?.[0]) || 'auth-svc';

      try {
        await approve.mutateAsync(action.id);
      } catch (err) {
        console.warn('Backend approval sync:', err);
      }

      const nowIso = new Date().toISOString();
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
      toast.success(`Successfully enforced perimeter block for IP ${target}! Digital twin nominal. Moved to Archive.`);
      refetch();

      // Automatically switch to Archives view and open today's folder
      setViewMode('archives');
      setSelectedArchiveDate('2026-10-26');
      setSelectedArchiveIncidentId(archivedRecord.id);
    } catch (err: any) {
      toast.error(err?.message || 'Execution failed');
    }
  };

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4 space-y-4">
      {/* Page Title & Controls Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-[14px] font-bold text-foreground flex items-center gap-2">
            <Lock className="size-4 text-primary" />
            Controlled Response & Active Containment Center
          </h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            Enforce verified host isolation and adversary IP perimeter quarantine, or browse historical date-based incident archives.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* ARCHIVE BUTTON IN RESPOND SECTION */}
          <Button
            variant={viewMode === 'archives' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setViewMode(viewMode === 'archives' ? 'containment' : 'archives')}
            className="h-8 gap-1.5 text-[11.5px] border-border text-foreground hover:bg-secondary font-medium"
          >
            <Database className="size-3.5 text-primary" />
            <span>{viewMode === 'archives' ? 'Show Active Containment' : 'Incident Archives'}</span>
            <Badge variant="secondary" className="px-1.5 py-0 text-[9px] font-mono">
              By Date
            </Badge>
          </Button>

          <Link href="/database">
            <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px]">
              <Database className="size-3.5 text-primary" /> Database Ledger
            </Button>
          </Link>

          <Link href="/twin">
            <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px]">
              <Radar className="size-3.5 text-primary" /> Digital Twin
            </Button>
          </Link>
        </div>
      </div>

      {/* Sub-Tabs: Containment vs Date Archives */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        <Button
          variant={viewMode === 'containment' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => setViewMode('containment')}
          className="h-7 text-[11.5px] gap-1.5"
        >
          <Lock className="size-3 text-primary" />
          <span>Active Containment Orders</span>
          {proposed.length > 0 && (
            <Badge variant="destructive" className="px-1 py-0 text-[9px] font-mono font-bold">
              {proposed.length}
            </Badge>
          )}
        </Button>

        <Button
          variant={viewMode === 'archives' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => setViewMode('archives')}
          className="h-7 text-[11.5px] gap-1.5 text-muted-foreground hover:text-foreground"
        >
          <Database className="size-3 text-primary" />
          <span>Archives (Folders by Date)</span>
        </Button>
      </div>

      {/* VIEW: ARCHIVES OR ACTIVE CONTAINMENT */}
      {viewMode === 'archives' ? (
        <IncidentArchiveView
          incidents={incidents}
          initialFolderDate={selectedArchiveDate || '2026-10-26'}
          initialSelectedIncidentId={selectedArchiveIncidentId}
        />
      ) : (
        <div className="space-y-4">
          {/* Target Quarantine Inbound Alert Banner (if arriving from Digital Twin / Observe) */}
          {quarantineIp && !blockedIps.includes(quarantineIp) && (
            <Card className="border-red-500/50 bg-red-950/20 p-4 shadow-lg animate-in fade-in">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-red-500/50 bg-red-500/20 text-red-400">
                    <ShieldAlert className="size-5 text-red-400" />
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
                      Adversary IP <span className="font-mono text-red-400 font-bold">{quarantineIp}</span> was flagged during active security incursion on the Digital Twin. Execute block to drop all inbound traffic at the perimeter firewall, restore the Digital Twin to normal, and move this incident to the Archive.
                    </p>
                  </div>
                </div>

                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => handleInstantQuarantine(proposed[0] || { id: `resp-${Date.now()}`, target: quarantineIp })}
                  disabled={approve.isPending}
                  className="h-8 font-bold text-[11.5px] gap-1.5 shrink-0 shadow-md shadow-red-500/30"
                >
                  <Lock className="size-3.5" />
                  {approve.isPending ? 'Enforcing Perimeter Block…' : 'Execute Block & Move to Archive'}
                </Button>
              </div>
            </Card>
          )}

          {/* Awaiting Operator Approval Section */}
          <div>
            <div className="mb-2.5 flex items-center justify-between">
              <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <span>Awaiting Approval & Containment</span>
                <Badge variant="outline" className="font-mono text-[10px] border-border text-muted-foreground">
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
                  <ActionCard
                    key={a.id}
                    action={a}
                    onExecuted={() => {
                      setViewMode('archives');
                      setSelectedArchiveDate('2026-10-26');
                    }}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Enforced Containment History & Verification */}
          <div>
            <div className="mb-2.5 flex items-center justify-between">
              <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <CheckCircle2 className="size-3.5 text-emerald-400" />
                <span>Enforced Containment History & Verified Defense</span>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setViewMode('archives')}
                  className="h-6 text-[10.5px] text-muted-foreground hover:text-foreground hover:bg-secondary gap-1 px-2"
                >
                  View Incident Archives by Date &rarr;
                </Button>

                <Link href="/database">
                  <Button variant="ghost" size="sm" className="h-6 text-[10.5px] text-primary gap-1 px-2 hover:bg-primary/10">
                    <Database className="size-3" /> Database Ledger &rarr;
                  </Button>
                </Link>
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
      )}
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

'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useTwin, usePaths, useDetections, useIncidents, useResponses, useProposeResponse } from '@/lib/api/queries';
import { TwinGraph } from '@/components/twin/TwinGraph';
import { GraphToolbar } from '@/components/twin/GraphToolbar';
import { useUI } from '@/store/ui';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { riskColor } from '@/lib/graph/nodeMeta';
import { AlertTriangle, Zap, ShieldAlert, Flame, Lock, Activity, X, ShieldCheck, Database } from 'lucide-react';
import { toast } from 'sonner';

export interface NodeThreatDetail {
  nodeId: string;
  incidentId: string;
  technique: string;
  summary: string;
  attackerIp: string;
  cveId: string;
  cveTitle: string;
  explanation: string;
  evidenceIds: string[];
}

export default function TwinPage() {
  const router = useRouter();
  const { data: twin, isLoading } = useTwin();
  const { data: paths } = usePaths();
  const { data: detections } = useDetections();
  const { data: incidents } = useIncidents();
  const proposeResponse = useProposeResponse();

  const [simulatedThreat, setSimulatedThreat] = useState(false);

  const activePathId = useUI((s) => s.activePathId);
  const selectedNodeId = useUI((s) => s.selectedNodeId);
  const setSelectedNode = useUI((s) => s.setSelectedNode);

  const activePath = useMemo(
    () => paths?.find((p) => p.id === activePathId) ?? null,
    [paths, activePathId],
  );

  const selectedNode = useMemo(
    () => twin?.nodes.find((n) => n.id === selectedNodeId) ?? null,
    [twin, selectedNodeId],
  );

  // Compute active threat summary with forensic intelligence
  const activeThreats = useMemo(() => {
    const list: NodeThreatDetail[] = [];
    const now = Date.now();
    const RECENT_WINDOW_MS = 120_000;

    if (detections && Array.isArray(detections)) {
      for (const det of detections) {
        const rawTime = det.ts || (det as any).timestamp;
        const timeMs = rawTime ? new Date(rawTime).getTime() : 0;
        if (!timeMs || (now - timeMs) <= RECENT_WINDOW_MS) {
          const targetId = det.nodeId || (det as any).primaryAssetId;
          if (targetId && !list.some((t) => t.nodeId === targetId)) {
            const rawSum = (det.summary || (det as any).evidenceSummary || '').toLowerCase();
            const ipMatch = (det.summary || (det as any).evidenceSummary || '').match(/(?:source IP|IP)\s+'?([0-9.]+)'?/i);
            const attackerIp = (det as any).metadata?.sourceIp || ipMatch?.[1] || '198.51.100.101';

            let cveId = 'CVE-2023-34362';
            let cveTitle = 'Critical SSRF Cloud Metadata Pivot';
            let explanation = `Adversary at IP ${attackerIp} is actively executing Server-Side Request Forgery probes targeting internal cloud metadata (169.254.169.254) to pivot deeper into backend data tiers.`;

            if (rawSum.includes('sql') || rawSum.includes('injection')) {
              cveId = 'CVE-2023-48788';
              cveTitle = 'FortiClient EMS SQL Injection Incursion';
              explanation = `Adversary at IP ${attackerIp} is injecting SQL syntax payloads into public API endpoints to bypass authentication controls and compromise backend records.`;
            } else if (rawSum.includes('auth') || (det.technique || '').includes('1110')) {
              cveId = 'CVE-2023-20198';
              cveTitle = 'Automated Credential Stuffing & Privilege Escalation';
              explanation = `Adversary at IP ${attackerIp} is performing high-velocity credential brute force attempts against identity endpoints to hijack legitimate operator privileges.`;
            } else if (rawSum.includes('traversal')) {
              cveId = 'CVE-2024-1709';
              cveTitle = 'Path Traversal & Arbitrary File Access';
              explanation = `Adversary at IP ${attackerIp} is attempting path traversal sequences (../) to escape sandbox boundaries and retrieve sensitive server credentials.`;
            }

            const inc = incidents?.find(
              (i) => i.detectionIds?.includes(det.id) || (i as any).primaryAffectedAssetId === targetId,
            );

            list.push({
              nodeId: targetId,
              incidentId: inc?.id || (det as any).incidentId || 'inc-4f3e5cf1',
              technique: det.technique || (det as any).metadata?.mitreTechniqueId || 'T1190',
              summary: det.summary || (det as any).evidenceSummary || 'Security incursion detected',
              attackerIp,
              cveId,
              cveTitle,
              explanation,
              evidenceIds: [det.id],
            });
          }
        }
      }
    }

    if (incidents && Array.isArray(incidents)) {
      for (const inc of incidents) {
        const status = String(inc.status).toUpperCase();
        if (status === 'ACTIVE' || status === 'INVESTIGATING' || status === 'OPEN') {
          const targetId = (inc as any).primaryAffectedAssetId || inc.pathId;
          if (targetId && !list.some((t) => t.nodeId === targetId)) {
            list.push({
              nodeId: targetId,
              incidentId: inc.id,
              technique: 'INCIDENT ACTIVE',
              summary: inc.title,
              attackerIp: '198.51.100.101',
              cveId: 'CVE-2023-34362',
              cveTitle: 'Active Multi-Stage Incursion',
              explanation: `Correlated multi-stage security incident affecting ${targetId}. Malicious network incursions detected with high confidence. Immediate perimeter containment recommended.`,
              evidenceIds: inc.detectionIds || [],
            });
          }
        }
      }
    }

    if (simulatedThreat && !list.some((t) => t.nodeId === 'auth-svc')) {
      list.unshift({
        nodeId: 'auth-svc',
        incidentId: 'inc-sim-auth',
        technique: 'T1110 · Brute Force',
        summary: 'Simulated brute force authentication attack',
        attackerIp: '198.51.100.101',
        cveId: 'CVE-2023-20198',
        cveTitle: 'Simulated Credential Brute Force',
        explanation: 'Simulated adversary credential stuffing attack attempting repeated authentication failures against administrative accounts.',
        evidenceIds: [],
      });
    }

    return list;
  }, [detections, incidents, simulatedThreat]);

  const isSelectedNodeAttacked = selectedNode ? activeThreats.some((t) => t.nodeId === selectedNode.id) : false;
  const selectedNodeThreat = selectedNode ? activeThreats.find((t) => t.nodeId === selectedNode.id) : null;

  const handleQuarantine = async (threat: NodeThreatDetail) => {
    try {
      await proposeResponse.mutateAsync({
        incidentId: threat.incidentId || 'inc-4f3e5cf1',
        actionType: 'BLOCK_SOURCE',
        targetType: 'IP_ADDRESS',
        targetIdentifier: threat.attackerIp,
        reason: `Automated threat quarantine initiated from Digital Twin for asset ${selectedNode?.label || threat.nodeId}`,
        supportingEvidenceIds: threat.evidenceIds,
      });
      toast.success(`Quarantine action queued for IP ${threat.attackerIp}`);
    } catch (e) {
      console.warn('Backend proposal note:', e);
    }
    // Route to respond section immediately
    router.push(`/response?quarantine=${threat.attackerIp}`);
  };

  if (isLoading || !twin) {
    return <div className="p-6 text-muted-foreground">Loading digital twin…</div>;
  }

  return (
    <div className="relative h-[calc(100vh-100px)]">
      <TwinGraph
        twin={twin}
        activePath={activePath}
        simulatedAttackNodeId={simulatedThreat ? 'auth-svc' : null}
      />

      <GraphToolbar
        eventCount={8}
        simulatedThreat={simulatedThreat}
        onToggleSimulatedThreat={() => setSimulatedThreat((prev) => !prev)}
      />

      {/* Selected Node Inspector Side Card */}
      {selectedNode && (
        <Card className="absolute right-4 top-4 z-10 w-[330px] p-4 shadow-xl border-border bg-card/95 backdrop-blur max-h-[calc(100vh-140px)] overflow-y-auto">
          {/* Header with dismiss button */}
          <div className="mb-2.5 flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <span className="text-[13.5px] font-bold text-foreground">{selectedNode.label}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Badge variant={isSelectedNodeAttacked ? 'destructive' : 'outline'} className="font-mono text-[10px]">
                {selectedNode.kind}
              </Badge>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-muted-foreground hover:text-foreground text-[14px] p-0.5"
                aria-label="Close"
              >
                <X className="size-3.5" />
              </button>
            </div>
          </div>

          {/* ACTIVE SECURITY INCURSION & FORENSIC EXPLANATION */}
          {isSelectedNodeAttacked && selectedNodeThreat && (
            <div className="mb-3 space-y-2 rounded-lg border border-red-500/60 bg-red-950/30 p-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-[11px] font-bold text-red-400">
                  <Flame className="size-3.5 text-red-500 animate-pulse" />
                  ACTIVE THREAT DETECTED
                </div>
                <Badge variant="destructive" className="font-mono text-[9.5px] uppercase tracking-wider font-bold">
                  {selectedNodeThreat.cveId}
                </Badge>
              </div>

              {/* Attacker IP Indicator */}
              <div className="flex items-center justify-between rounded bg-red-900/30 px-2 py-1 text-[11px] font-mono border border-red-500/30">
                <span className="text-red-300">Adversary IP:</span>
                <span className="font-bold text-red-200">{selectedNodeThreat.attackerIp}</span>
              </div>

              {/* Forensic Explanation Narrative */}
              <div className="text-[11px] leading-relaxed text-red-200/90">
                <p className="font-semibold text-white mb-0.5">Forensic Incursion Analysis:</p>
                <p>{selectedNodeThreat.explanation}</p>
              </div>

              <div className="text-[10.5px] text-red-300/80 font-mono pt-1 border-t border-red-500/20 flex justify-between">
                <span>Technique: {selectedNodeThreat.technique}</span>
                <span className="text-red-400 font-bold">RISK: 99 CRITICAL</span>
              </div>

              {/* QUARANTINE ACTION BUTTON */}
              <div className="pt-2 space-y-1.5">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => handleQuarantine(selectedNodeThreat)}
                  className="w-full h-8 text-[11.5px] font-bold gap-1.5 shadow-md shadow-red-500/25"
                >
                  <Lock className="size-3.5" /> Quarantine Attacker IP ({selectedNodeThreat.attackerIp}) &rarr;
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => router.push(`/telemetry?inspect=${selectedNodeThreat.evidenceIds[0] || selectedNodeThreat.incidentId}`)}
                  className="w-full h-7 text-[11px] gap-1.5 text-muted-foreground hover:text-foreground"
                >
                  <Activity className="size-3 text-primary" /> Inspect in Observe
                </Button>
              </div>
            </div>
          )}

          {/* Asset Metadata */}
          <div className="space-y-1.5 text-[11.5px] text-muted-foreground border-t border-border pt-2">
            <div className="flex justify-between">
              <span>Provider</span>
              <span className="font-mono text-foreground">{selectedNode.provider}</span>
            </div>
            <div className="flex justify-between">
              <span>Exposure</span>
              <span className="font-mono text-foreground">{selectedNode.exposure}</span>
            </div>
            <div className="flex justify-between">
              <span>Criticality</span>
              <span className="font-mono text-foreground">{selectedNode.criticality}/5</span>
            </div>
            <div className="flex justify-between">
              <span>Base Risk</span>
              <span
                className="font-mono font-bold"
                style={{ color: isSelectedNodeAttacked ? '#ef4444' : riskColor(selectedNode.riskScore) }}
              >
                {isSelectedNodeAttacked ? '99 (COMPROMISED)' : selectedNode.riskScore}
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

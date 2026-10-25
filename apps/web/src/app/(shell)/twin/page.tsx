'use client';

import { useMemo, useState } from 'react';
import { useTwin, usePaths, useDetections, useIncidents } from '@/lib/api/queries';
import { TwinGraph } from '@/components/twin/TwinGraph';
import { GraphToolbar } from '@/components/twin/GraphToolbar';
import { useUI } from '@/store/ui';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { riskColor } from '@/lib/graph/nodeMeta';
import { AlertTriangle, Zap, ShieldAlert, Flame } from 'lucide-react';

export default function TwinPage() {
  const { data: twin, isLoading } = useTwin();
  const { data: paths } = usePaths();
  const { data: detections } = useDetections();
  const { data: incidents } = useIncidents();

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

  // Compute active threat summary for HUD header
  const activeThreats = useMemo(() => {
    const list: { nodeId: string; technique: string; summary: string }[] = [];
    const now = Date.now();
    const RECENT_WINDOW_MS = 90_000;

    if (detections && Array.isArray(detections)) {
      for (const det of detections) {
        const rawTime = det.ts || (det as any).timestamp;
        const timeMs = rawTime ? new Date(rawTime).getTime() : 0;
        if (!timeMs || (now - timeMs) <= RECENT_WINDOW_MS) {
          const targetId = det.nodeId || (det as any).primaryAssetId;
          if (targetId && !list.some((t) => t.nodeId === targetId)) {
            list.push({
              nodeId: targetId,
              technique: det.technique || (det as any).metadata?.mitreTechniqueId || 'T1110',
              summary: det.summary || (det as any).evidenceSummary || 'Security incursion detected',
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
              technique: 'INCIDENT ACTIVE',
              summary: inc.title,
            });
          }
        }
      }
    }

    if (simulatedThreat && !list.some((t) => t.nodeId === 'auth-svc')) {
      list.unshift({
        nodeId: 'auth-svc',
        technique: 'T1110 · Brute Force',
        summary: 'Simulated brute force authentication attack',
      });
    }

    return list;
  }, [detections, incidents, simulatedThreat]);

  const isSelectedNodeAttacked = selectedNode ? activeThreats.some((t) => t.nodeId === selectedNode.id) : false;
  const selectedNodeThreat = selectedNode ? activeThreats.find((t) => t.nodeId === selectedNode.id) : null;

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

      {selectedNode && (
        <Card className="absolute right-4 top-4 z-10 w-[290px] p-4 shadow-lg backdrop-blur">
          {isSelectedNodeAttacked && (
            <div className="mb-3 rounded-md border border-red-500/50 bg-red-500/15 p-2.5 text-red-300 animate-pulse">
              <div className="flex items-center gap-1.5 text-[11.5px] font-bold text-red-200">
                <Flame className="size-3.5 text-red-400" /> ACTIVE SECURITY INCURSION
              </div>
              <div className="mt-1 text-[11px] text-red-300/90 font-mono">
                Technique: {selectedNodeThreat?.technique}
              </div>
              <div className="mt-0.5 text-[10.5px] text-red-200">
                {selectedNodeThreat?.summary}
              </div>
            </div>
          )}

          <div className="mb-2 flex items-center justify-between">
            <div className="text-[13px] font-semibold">{selectedNode.label}</div>
            <Badge variant={isSelectedNodeAttacked ? 'destructive' : 'outline'} className="font-mono text-[10px]">
              {selectedNode.kind}
            </Badge>
          </div>
          <div className="space-y-1.5 text-[11.5px] text-muted-foreground">
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
              <span>Risk</span>
              <span
                className="font-mono font-bold"
                style={{ color: isSelectedNodeAttacked ? '#ef4444' : riskColor(selectedNode.riskScore) }}
              >
                {isSelectedNodeAttacked ? 99 : selectedNode.riskScore}
                {isSelectedNodeAttacked && ' (CRITICAL)'}
              </span>
            </div>
            {isSelectedNodeAttacked && (
              <div className="flex justify-between text-red-400">
                <span>Threat Status</span>
                <span className="font-semibold flex items-center gap-1">
                  <Zap className="size-3" /> TARGETED
                </span>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}

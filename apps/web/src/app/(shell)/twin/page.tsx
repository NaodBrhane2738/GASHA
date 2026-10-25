'use client';

import { useMemo } from 'react';
import { useTwin, usePaths } from '@/lib/api/queries';
import { TwinGraph } from '@/components/twin/TwinGraph';
import { GraphToolbar } from '@/components/twin/GraphToolbar';
import { PathLegend } from '@/components/twin/PathLegend';
import { useUI } from '@/store/ui';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { riskColor } from '@/lib/graph/nodeMeta';
import { useIncidents } from '@/lib/api/queries';

export default function TwinPage() {
  const { data: twin, isLoading } = useTwin();
  const { data: paths } = usePaths();
  const activePathId = useUI((s) => s.activePathId);
  const selectedNodeId = useUI((s) => s.selectedNodeId);
  const { data: incidents } = useIncidents();
  const attacked = useMemo(
    () => (twin?.nodes ?? []).filter((n) => n.metadata?.status === 'under-attack').map((n) => n.id),
    [twin],
  );
  const openIncidents = incidents?.filter((i) => i.status !== 'resolved') ?? [];

  const activePath = useMemo(
    () => paths?.find((p) => p.id === activePathId) ?? null,
    [paths, activePathId],
  );

  const selectedNode = useMemo(
    () => twin?.nodes.find((n) => n.id === selectedNodeId) ?? null,
    [twin, selectedNodeId],
  );

  if (isLoading || !twin) {
    return <div className="p-6 text-muted-foreground">Loading digital twin…</div>;
  }

  return (
    <div className="relative h-[calc(100vh-150px)] min-h-[480px] lg:h-[calc(100vh-100px)]">
      <TwinGraph twin={twin} activePath={activePath} highlightNodeIds={attacked} />
      <GraphToolbar eventCount={0} />
      <PathLegend />
      <div className="pointer-events-none absolute bottom-4 left-1/2 z-10 -translate-x-1/2 rounded-md border bg-card/90 px-3 py-1.5 text-[11px] backdrop-blur">
        {attacked.length ? (
          <span>
            <span className="font-semibold text-[hsl(var(--critical))]">{attacked.length} assets under active attack</span>
            <span className="text-muted-foreground"> · {openIncidents.length} open incident{openIncidents.length === 1 ? '' : 's'}</span>
          </span>
        ) : (
          <span className="text-muted-foreground">No assets under active attack</span>
        )}
      </div>

      {selectedNode && (
        <Card className="absolute right-4 top-16 z-10 w-[min(280px,calc(100%-2rem))] p-4 sm:top-4">
          <div className="mb-2 flex items-center justify-between">
            <div className="text-[13px] font-semibold">{selectedNode.label}</div>
            <Badge variant="outline" className="font-mono text-[10px]">
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
              <span>Status</span>
              <span className="font-mono text-foreground">{String(selectedNode.metadata?.status ?? 'normal')}</span>
            </div>
            <div className="flex justify-between">
              <span>Risk</span>
              <span className="font-mono" style={{ color: riskColor(selectedNode.riskScore) }}>
                {selectedNode.riskScore}
              </span>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
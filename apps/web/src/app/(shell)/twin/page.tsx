'use client';

import { useMemo } from 'react';
import { useTwin, usePaths } from '@/lib/api/queries';
import { TwinGraph } from '@/components/twin/TwinGraph';
import { GraphToolbar } from '@/components/twin/GraphToolbar';
import { useUI } from '@/store/ui';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { riskColor } from '@/lib/graph/nodeMeta';

export default function TwinPage() {
  const { data: twin, isLoading } = useTwin();
  const { data: paths } = usePaths();
  const activePathId = useUI((s) => s.activePathId);
  const selectedNodeId = useUI((s) => s.selectedNodeId);

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
    <div className="relative h-[calc(100vh-100px)]">
      <TwinGraph twin={twin} activePath={activePath} />
      <GraphToolbar eventCount={8} />

      {selectedNode && (
        <Card className="absolute right-4 top-4 z-10 w-[280px] p-4">
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
'use client';

import { usePaths, useTwin, useResponses } from '@/lib/api/queries';
import { ShieldCheck, Database, Check } from 'lucide-react';
import Link from 'next/link';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useUI } from '@/store/ui';
import { riskColor } from '@/lib/graph/nodeMeta';
import { TwinGraph } from '@/components/twin/TwinGraph';

export default function PathsPage() {
  const { data: paths } = usePaths();
  const { data: twin } = useTwin();
  const activePathId = useUI((s) => s.activePathId);
  const setActivePath = useUI((s) => s.setActivePath);

  const active = paths?.find((p) => p.id === activePathId) ?? null;

  return (
    <div className="grid h-[calc(100vh-100px)] grid-cols-[360px_1fr]">
      <div className="overflow-y-auto border-r border-border p-4">
        <h2 className="mb-3 text-[13px] font-semibold">Attack Paths</h2>
        <div className="space-y-2">
          {paths?.map((p) => (
            <Card
              key={p.id}
              className={`cursor-pointer p-3 transition-all ${
                activePathId === p.id ? 'ring-2 ring-primary' : 'hover:border-muted-foreground/40'
              }`}
              onClick={() => setActivePath(p.id === activePathId ? null : p.id)}
            >
              <div className="mb-1.5 flex items-center justify-between">
                <span className="font-mono text-[11px] text-muted-foreground">
                  {p.entryNodeId || (p as any).entryPointAssetId} → {p.crownJewelNodeId || (p as any).targetAssetId}
                </span>
                <span className="font-mono text-[12px]" style={{ color: riskColor(p.riskScore || (p as any).pathScore || 0) }}>
                  {p.riskScore || (p as any).pathScore || 0}
                </span>
              </div>
              <div className="mb-2 flex flex-wrap gap-1">
                {(p.techniques ?? []).map((t) => (
                  <Badge key={t} variant="outline" className="font-mono text-[10px]">
                    {t}
                  </Badge>
                ))}
              </div>
              <div className="flex items-center justify-between text-[10.5px] text-muted-foreground">
                <span>likelihood {((p.likelihood ?? 0.75) * 100).toFixed(0)}%</span>
                <span>impact {((p.impact ?? 0.9) * 100).toFixed(0)}%</span>
              </div>
            </Card>
          ))}
        </div>
      </div>

      <div className="relative">
        {twin && <TwinGraph twin={twin} activePath={active} />}
        {active && (
          <div className="absolute bottom-4 left-4 right-4 z-10 rounded-lg border border-border bg-card/95 p-3 backdrop-blur">
            <div className="flex items-center justify-between">
              <div className="text-[12.5px]">
                <span className="font-medium">Path {active.id}</span>
                <span className="ml-2 text-muted-foreground">
                  {(active.nodeIds ?? []).length} nodes · {(active.edgeIds ?? []).length} edges
                </span>
              </div>
              <Button size="sm" variant="destructive">
                Open response options
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
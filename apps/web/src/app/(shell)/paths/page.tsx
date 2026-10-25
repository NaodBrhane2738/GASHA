'use client';

import { usePaths, useTwin } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import Link from 'next/link';
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
    <div className="grid grid-cols-1 lg:h-[calc(100vh-100px)] lg:grid-cols-[360px_1fr]">
      <div className="max-h-[45vh] overflow-y-auto border-b border-border p-4 lg:max-h-none lg:border-b-0 lg:border-r">
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
                  {p.entryNodeId} → {p.crownJewelNodeId}
                </span>
                <span className="flex items-center gap-2">
                  <Badge variant="outline" className={`text-[10px] ${p.status === 'mitigated' ? 'text-[hsl(var(--low))]' : 'text-[hsl(var(--high))]'}`}>
                    {p.status}
                  </Badge>
                  <span className="font-mono text-[12px]" style={{ color: riskColor(p.riskScore) }}>
                    {p.riskScore}
                  </span>
                </span>
              </div>
              <div className="mb-2 flex flex-wrap gap-1">
                {p.techniques.map((t) => (
                  <Badge key={t} variant="outline" className="font-mono text-[10px]">
                    {t}
                  </Badge>
                ))}
              </div>
              <div className="flex items-center justify-between text-[10.5px] text-muted-foreground">
                <span>likelihood {(p.likelihood * 100).toFixed(0)}%</span>
                <span>impact {(p.impact * 100).toFixed(0)}%</span>
              </div>
            </Card>
          ))}
        </div>
      </div>

      <div className="relative h-[60vh] lg:h-auto">
        {twin && <TwinGraph twin={twin} activePath={active} />}
        {active && (
          <div className="absolute bottom-4 left-4 right-4 z-10 rounded-lg border border-border bg-card/95 p-3 backdrop-blur">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-[12.5px]">
                <span className="font-medium">Path {active.id}</span>
                <span className="ml-2 text-muted-foreground">
                  {active.nodeIds.length} nodes · {active.edgeIds.length} edges
                </span>
              </div>
              <Button asChild size="sm" variant={active.status === 'mitigated' ? 'outline' : 'destructive'}>
                <Link href="/response">{active.status === 'mitigated' ? 'View response history' : 'Open response options'}</Link>
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
'use client';

import { useState } from 'react';
import { useDetections } from '@/lib/api/queries';
import { useEventStream } from '@/lib/realtime/useEventStream';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';
import type { Detection } from '@/types/domain';

export default function TelemetryPage() {
  const { data: initial } = useDetections();
  const [live, setLive] = useState<Detection[]>([]);
  const { connected } = useEventStream((d) =>
    setLive((prev) => [d, ...prev].slice(0, 40)),
  );

  const all = [...live, ...(initial ?? [])].slice(0, 80);

  return (
    <div className="h-[calc(100vh-100px)] overflow-hidden p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-[13px] font-semibold">Live Telemetry & Detections</h2>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span
            className="inline-block size-2 rounded-full"
            style={{
              background: connected ? 'hsl(var(--low))' : 'hsl(var(--medium))',
            }}
          />
          {connected ? 'streaming' : 'connecting…'}
        </div>
      </div>

      <Card className="overflow-hidden">
        <div className="max-h-[calc(100vh-200px)] overflow-y-auto">
          {all.map((d) => (
            <div
              key={d.id}
              className="flex items-center gap-3 border-b border-border px-3 py-2 text-[12px] last:border-0 hover:bg-secondary/40"
            >
              <span className="w-[60px] font-mono text-[10.5px] text-muted-foreground">
                {new Date(d.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </span>
              <span
                className="w-[70px] rounded px-1.5 py-0.5 text-center text-[10.5px] font-medium"
                style={{
                  background: `${SEVERITY_TOKEN[d.severity]}25`,
                  color: SEVERITY_TOKEN[d.severity],
                }}
              >
                {d.severity}
              </span>
              <span className="w-[110px] font-mono text-[11px] text-muted-foreground">
                {d.technique}
              </span>
              <span className="w-[130px] font-mono text-[11px] text-muted-foreground">
                {d.nodeId}
              </span>
              <span className="flex-1 truncate">{d.summary}</span>
              <span className="font-mono text-[10.5px] text-muted-foreground">
                {(d.confidence * 100).toFixed(0)}%
              </span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
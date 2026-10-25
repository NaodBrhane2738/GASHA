'use client';

import { useDetections } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';

export default function DetectionsPage() {
  const { data } = useDetections();
  const counts = (data ?? []).reduce<Record<string, number>>((a, d) => {
    a[d.severity] = (a[d.severity] ?? 0) + 1;
    return a;
  }, {});

  return (
    <div className="h-full overflow-y-auto p-3 sm:p-4 lg:h-[calc(100vh-100px)]">
      <h2 className="mb-4 text-[13px] font-semibold">Behavioral Detections</h2>
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <Card key={s} className="p-3">
            <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">{s}</div>
            <div className="font-mono text-[22px]" style={{ color: SEVERITY_TOKEN[s] }}>
              {counts[s] ?? 0}
            </div>
          </Card>
        ))}
      </div>

      <Card className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-[12px]">
          <thead className="border-b border-border bg-secondary/50 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground">
            <tr>
              <th className="px-3 py-2">Time</th>
              <th className="px-3 py-2">Rule</th>
              <th className="px-3 py-2">Node</th>
              <th className="px-3 py-2">Technique</th>
              <th className="px-3 py-2">Summary</th>
              <th className="px-3 py-2">Conf.</th>
            </tr>
          </thead>
          <tbody>
            {data?.map((d) => (
              <tr key={d.id} className="border-b border-border last:border-0 hover:bg-secondary/30">
                <td className="px-3 py-2 font-mono text-[10.5px] text-muted-foreground">
                  {new Date(d.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </td>
                <td className="px-3 py-2">{d.rule}</td>
                <td className="px-3 py-2 font-mono text-[11px]">{d.nodeId}</td>
                <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                  {d.technique}
                </td>
                <td className="px-3 py-2 text-muted-foreground">{d.summary}</td>
                <td className="px-3 py-2 font-mono text-[11px]">
                  {(d.confidence * 100).toFixed(0)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
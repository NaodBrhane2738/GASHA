'use client';

import { useDetections } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';

export default function DetectionsPage() {
  const { data } = useDetections();
  const counts = (data ?? []).reduce<Record<string, number>>((a, d) => {
    const sev = (d.severity ?? 'low').toLowerCase();
    a[sev] = (a[sev] ?? 0) + 1;
    return a;
  }, {});

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4">
      <h2 className="mb-4 text-[13px] font-semibold">Behavioral Detections</h2>
      <div className="mb-4 grid grid-cols-4 gap-3">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <Card key={s} className="p-3">
            <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">{s}</div>
            <div className="font-mono text-[22px]" style={{ color: SEVERITY_TOKEN[s] }}>
              {counts[s] ?? 0}
            </div>
          </Card>
        ))}
      </div>

      <Card className="overflow-hidden">
        <table className="w-full text-[12px]">
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
            {data?.map((d) => {
              const ruleName = typeof d.rule === 'object' && d.rule !== null
                ? (d.rule.name || d.rule.ruleId)
                : String(d.rule ?? '');
              const timeVal = d.ts || (d as any).timestamp || new Date().toISOString();
              const nodeVal = d.nodeId || (d as any).primaryAssetId || 'unknown';
              const techVal = d.technique || ((d as any).metadata?.mitreTechniqueId) || 'T1059';
              const summaryVal = d.summary || (d as any).evidenceSummary || '';

              return (
                <tr key={d.id} className="border-b border-border last:border-0 hover:bg-secondary/30">
                  <td className="px-3 py-2 font-mono text-[10.5px] text-muted-foreground">
                    {new Date(timeVal).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                  <td className="px-3 py-2 font-medium">{ruleName}</td>
                  <td className="px-3 py-2 font-mono text-[11px]">{nodeVal}</td>
                  <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">
                    {techVal}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{summaryVal}</td>
                  <td className="px-3 py-2 font-mono text-[11px]">
                    {(d.confidence * 100).toFixed(0)}%
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
'use client';

import { useRouter } from 'next/navigation';
import { useDetections, useIncidents } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';
import { ShieldAlert, ArrowRight } from 'lucide-react';

export default function DetectionsPage() {
  const router = useRouter();
  const { data } = useDetections();
  const { data: incidents } = useIncidents();

  const counts = (data ?? []).reduce<Record<string, number>>((a, d) => {
    const sev = (d.severity ?? 'low').toLowerCase();
    a[sev] = (a[sev] ?? 0) + 1;
    return a;
  }, {});

  const activeIncidents = (incidents ?? []).filter((inc) => {
    const s = String(inc.status).toLowerCase();
    return s === 'open' || s === 'active' || s === 'investigating';
  });

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h2 className="text-[14px] font-bold text-foreground flex items-center gap-2">
            <ShieldAlert className="size-4 text-primary" />
            Behavioral Detections & Correlated Incidents
          </h2>
          <p className="text-[11.5px] text-muted-foreground">
            Touch or click any incident or detection to inspect live telemetry in the Observe console.
          </p>
        </div>
      </div>

      {/* Severity Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <Card key={s} className="p-3 border-border">
            <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">{s}</div>
            <div className="font-mono text-[22px] font-bold" style={{ color: SEVERITY_TOKEN[s] }}>
              {counts[s] ?? 0}
            </div>
          </Card>
        ))}
      </div>

      {/* Correlated Active Incidents Section */}
      {activeIncidents.length > 0 && (
        <div className="space-y-2">
          <div className="text-[12px] font-semibold text-foreground flex items-center gap-2">
            <ShieldAlert className="size-3.5 text-red-400" />
            Active Correlated Incidents
            <Badge variant="outline" className="text-[10px] font-mono border-red-500/40 text-red-400">
              {activeIncidents.length} Under Active Attack
            </Badge>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {activeIncidents.map((inc) => (
              <Card
                key={inc.id}
                onClick={() => router.push(`/telemetry?inspect=${inc.detectionIds?.[0] || inc.id}`)}
                className="p-3.5 border-border bg-card/80 hover:border-primary/60 hover:bg-secondary/40 transition-all cursor-pointer group shadow-sm"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span
                      className="rounded px-1.5 py-0.5 text-[10px] font-bold uppercase font-mono"
                      style={{
                        background: `${SEVERITY_TOKEN[inc.severity] || '#ef4444'}25`,
                        color: SEVERITY_TOKEN[inc.severity] || '#ef4444',
                      }}
                    >
                      {inc.severity}
                    </span>
                    <span className="font-semibold text-[13px] group-hover:text-primary transition-colors">
                      {inc.title}
                    </span>
                  </div>
                  <Badge variant="outline" className="text-[10px] font-mono shrink-0">
                    {inc.status}
                  </Badge>
                </div>
                <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono">
                  <div className="flex items-center gap-3">
                    <span className="text-primary font-semibold">{inc.id}</span>
                    <span>{inc.detectionIds?.length ?? 1} detections</span>
                    <span>confidence {(inc.confidence * 100).toFixed(0)}%</span>
                  </div>
                  <span className="inline-flex items-center gap-1 text-primary text-[11.5px] font-sans font-medium group-hover:translate-x-0.5 transition-transform">
                    Observe <ArrowRight className="size-3" />
                  </span>
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Detections Grid/Table */}
      <Card className="overflow-hidden border-border">
        <div className="px-3 py-2.5 bg-secondary/30 border-b border-border flex items-center justify-between">
          <span className="text-[12px] font-semibold text-foreground">
            Telemetry Detection Feeds ({data?.length ?? 0})
          </span>
          <span className="text-[11px] text-muted-foreground">
            Click row to view in Observe
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[12px]">
            <thead className="border-b border-border bg-secondary/50 text-left text-[10.5px] uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Rule</th>
                <th className="px-3 py-2">Node</th>
                <th className="px-3 py-2">Technique</th>
                <th className="px-3 py-2">Summary</th>
                <th className="px-3 py-2">Conf.</th>
                <th className="px-3 py-2 text-right">Observe</th>
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
                const sev = (d.severity || 'low').toLowerCase();

                return (
                  <tr
                    key={d.id}
                    onClick={() => router.push(`/telemetry?inspect=${d.id}`)}
                    className="border-b border-border last:border-0 hover:bg-secondary/40 cursor-pointer transition-colors group"
                  >
                    <td className="px-3 py-2.5 font-mono text-[10.5px] text-muted-foreground whitespace-nowrap">
                      {new Date(timeVal).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                    <td className="px-3 py-2.5">
                      <span
                        className="rounded px-1.5 py-0.5 text-[9.5px] font-bold uppercase font-mono"
                        style={{
                          background: `${SEVERITY_TOKEN[sev as keyof typeof SEVERITY_TOKEN] || '#94a3b8'}20`,
                          color: SEVERITY_TOKEN[sev as keyof typeof SEVERITY_TOKEN] || '#94a3b8',
                        }}
                      >
                        {sev}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-medium group-hover:text-primary transition-colors">
                      {ruleName}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-foreground">
                      {nodeVal}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground whitespace-nowrap">
                      {techVal}
                    </td>
                    <td className="px-3 py-2.5 text-muted-foreground max-w-[320px] truncate">
                      {summaryVal}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px]">
                      {(d.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="px-3 py-2.5 text-right whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium text-primary opacity-80 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all">
                        Observe <ArrowRight className="size-3" />
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

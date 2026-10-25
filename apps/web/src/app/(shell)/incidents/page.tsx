'use client';

import Link from 'next/link';
import { useIncidents } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';
import { ArrowRight, Activity } from 'lucide-react';

export default function IncidentsPage() {
  const { data } = useIncidents();

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2 className="text-[13px] font-semibold">Correlated Incidents</h2>
          <p className="text-[11.5px] text-muted-foreground">
            Correlated multi-stage security incidents. Click to investigate or jump straight to Observe.
          </p>
        </div>
      </div>
      <div className="space-y-2">
        {data?.map((inc) => (
          <div key={inc.id} className="relative group">
            <Link href={`/incidents/${inc.id}`} className="block">
              <Card className="p-4 transition-all hover:border-primary/50 hover:bg-secondary/20">
                <div className="mb-2 flex items-center gap-2">
                  <span
                    className="rounded px-1.5 py-0.5 text-[10.5px] font-medium"
                    style={{
                      background: `${SEVERITY_TOKEN[inc.severity]}25`,
                      color: SEVERITY_TOKEN[inc.severity],
                    }}
                  >
                    {inc.severity}
                  </span>
                  <span className="font-medium text-[13px]">{inc.title}</span>
                  <Badge variant="outline" className="ml-auto text-[10px]">
                    {inc.status}
                  </Badge>
                </div>
                <div className="flex flex-wrap items-center gap-4 text-[11.5px] text-muted-foreground">
                  <span className="font-mono text-primary font-semibold">{inc.id}</span>
                  <span>{inc.detectionIds.length} detections</span>
                  <span>path: {inc.pathId}</span>
                  <span>confidence {(inc.confidence * 100).toFixed(0)}%</span>
                  <span className="ml-auto flex items-center gap-3">
                    <span>opened {new Date(inc.openedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    <Link
                      href={`/telemetry?inspect=${inc.detectionIds?.[0] || inc.id}`}
                      className="inline-flex items-center gap-1 rounded bg-primary/10 px-2 py-1 text-[11px] font-medium text-primary hover:bg-primary/20 transition-colors"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <Activity className="size-3" /> Observe <ArrowRight className="size-3" />
                    </Link>
                  </span>
                </div>
              </Card>
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}

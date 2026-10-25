'use client';

import Link from 'next/link';
import { useIncidents } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';

export default function IncidentsPage() {
  const { data } = useIncidents();

  return (
    <div className="h-full overflow-y-auto p-3 sm:p-4 lg:h-[calc(100vh-100px)]">
      <h2 className="mb-4 text-[13px] font-semibold">Correlated Incidents</h2>
      <div className="space-y-2">
        {data?.map((inc) => (
          <Link key={inc.id} href={`/incidents/${inc.id}`} className="block">
            <Card className="p-4 transition-all hover:border-muted-foreground/40">
              <div className="mb-2 flex flex-wrap items-center gap-2">
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
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-muted-foreground">
                <span className="font-mono">{inc.id}</span>
                <span>{inc.detectionIds.length} detections</span>
                {inc.pathId && <span>path: {inc.pathId}</span>}
                <span>risk {inc.riskBefore}{inc.riskAfter !== undefined ? ` → ${inc.riskAfter}` : ''}</span>
                <span>confidence {(inc.confidence * 100).toFixed(0)}%</span>
                <span className="ml-auto">
                  opened {new Date(inc.openedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              </div>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
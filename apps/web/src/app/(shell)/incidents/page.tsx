'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useIncidents } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';
import { ArrowRight, Activity, Database, GitMerge } from 'lucide-react';
import { IncidentArchiveView } from '@/components/archive/IncidentArchiveView';

export default function IncidentsPage() {
  const { data } = useIncidents();
  const [viewMode, setViewMode] = useState<'live' | 'archives'>('live');

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4 space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-[14px] font-bold text-foreground flex items-center gap-2">
            <GitMerge className="size-4 text-primary" />
            Correlated Incidents & Reconstructed Incursions
          </h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            Correlated multi-stage security incidents. Switch between live active telemetry correlation and historical date-based archives.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* ARCHIVES BUTTON */}
          <Button
            variant={viewMode === 'archives' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setViewMode(viewMode === 'archives' ? 'live' : 'archives')}
            className="h-8 gap-1.5 text-[11.5px] border-border text-foreground hover:bg-secondary font-medium"
          >
            
            <span>{viewMode === 'archives' ? 'Show Active Incursions' : 'Incident Archives'}</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              By Date
            </Badge>
          </Button>

          <Link href="/database">
            <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px]">
              <Database className="size-3.5 text-primary" /> Database Ledger
            </Button>
          </Link>
        </div>
      </div>

      {/* Main Content: Either Date-based Folder Archive OR Active Incidents */}
      {viewMode === 'archives' ? (
        <IncidentArchiveView incidents={data} />
      ) : (
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
                    <span>confidence {((inc.confidence || 0.9) * 100).toFixed(0)}%</span>
                    <span className="ml-auto flex items-center gap-3">
                      <span>opened {new Date(inc.openedAt || inc.createdAt || '').toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
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
      )}
    </div>
  );
}

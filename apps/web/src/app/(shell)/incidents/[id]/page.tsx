'use client';

import { use } from 'react';
import { useIncident, useStory, usePaths, useTwin } from '@/lib/api/queries';
import { StoryTimeline } from '@/components/story/StoryTimeline';
import { KillChainStrip } from '@/components/story/KillChainStrip';
import { TwinGraph } from '@/components/twin/TwinGraph';
import { GraphToolbar } from '@/components/twin/GraphToolbar';
import { useUI } from '@/store/ui';
import { useReplay } from '@/hooks/useReplay';
import { RiskDelta } from '@/components/risk/RiskDelta';
import Link from 'next/link';
import { Badge } from '@/components/ui/badge';

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data: incident } = useIncident(id);
  const { data: story } = useStory(id);
  const { data: paths } = usePaths();
  const { data: twin } = useTwin();
  const setSelectedIncident = useUI((s) => s.setSelectedIncident);

  if (incident && useUI.getState().selectedIncidentId !== incident.id) {
    setSelectedIncident(incident.id);
  }

  const path = paths?.find((p) => p.id === incident?.pathId) ?? null;
  const events = story ?? [];
  const replay = useReplay(events.length);
  // Show the whole story unless a replay is stepping through it.
  const visibleCount = replay.playing ? replay.index + 1 : events.length;
  const visible = events.slice(0, visibleCount);

  const highlightNodeIds = visible.map((e) => e.nodeId);

  return (
    <div className="grid grid-cols-1 lg:h-[calc(100vh-100px)] lg:grid-cols-[1fr_420px]">
      <div className="relative h-[50vh] border-b border-border lg:h-auto lg:border-b-0 lg:border-r">
        {twin && (
          <TwinGraph
            twin={twin}
            activePath={path}
            highlightNodeIds={highlightNodeIds}
          />
        )}
        <GraphToolbar eventCount={events.length} />
        {!replay.playing && events.length > 0 && (
          <div className="pointer-events-none absolute bottom-4 left-4 z-10 rounded-md border bg-card/90 px-2.5 py-1 text-[10.5px] text-muted-foreground backdrop-blur">
            Press “Replay attack” to step through the {events.length} events
          </div>
        )}
      </div>

      <div className="flex flex-col lg:overflow-hidden">
        <div className="border-b border-border p-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <h2 className="text-[13.5px] font-semibold">{incident?.title ?? 'Incident not found'}</h2>
            {incident && <Badge variant="outline" className="text-[10px]">{incident.status}</Badge>}
          </div>
          {!incident && (
            <Link href="/incidents" className="text-[11.5px] text-primary hover:underline">Back to incidents</Link>
          )}
          {incident && (
            <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground">
              <span className="font-mono">{incident.id}</span>
              <span>confidence {(incident.confidence * 100).toFixed(0)}%</span>
              <RiskDelta before={incident.riskBefore} after={incident.riskAfter} />
              <Link href="/response" className="text-primary hover:underline">Response →</Link>
            </div>
          )}
        </div>

        <div className="border-b border-border p-4">
          <KillChainStrip events={events} />
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          <StoryTimeline events={events} visibleCount={visibleCount} />
        </div>
      </div>
    </div>
  );
}
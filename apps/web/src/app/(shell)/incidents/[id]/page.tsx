'use client';

import { use } from 'react';
import { useIncident, useStory, usePaths, useTwin } from '@/lib/api/queries';
import { StoryTimeline } from '@/components/story/StoryTimeline';
import { KillChainStrip } from '@/components/story/KillChainStrip';
import { TwinGraph } from '@/components/twin/TwinGraph';
import { GraphToolbar } from '@/components/twin/GraphToolbar';
import { Card } from '@/components/ui/card';
import { useUI } from '@/store/ui';
import { useReplay } from '@/hooks/useReplay';
import { RiskDelta } from '@/components/risk/RiskDelta';

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
  const visible = events.slice(0, replay.index + 1);

  const highlightNodeIds = visible.map((e) => e.nodeId);

  return (
    <div className="grid h-[calc(100vh-100px)] grid-cols-[1fr_420px]">
      <div className="relative border-r border-border">
        {twin && (
          <TwinGraph
            twin={twin}
            activePath={path}
            highlightNodeIds={highlightNodeIds}
          />
        )}
        <GraphToolbar eventCount={events.length} />
      </div>

      <div className="flex flex-col overflow-hidden">
        <div className="border-b border-border p-4">
          <div className="mb-2 flex items-center gap-2">
            <h2 className="text-[13.5px] font-semibold">{incident?.title ?? 'Loading…'}</h2>
          </div>
          {incident && (
            <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
              <span className="font-mono">{incident.id}</span>
              <span>confidence {(incident.confidence * 100).toFixed(0)}%</span>
              <RiskDelta before={incident.riskBefore} after={incident.riskAfter} />
            </div>
          )}
        </div>

        <div className="border-b border-border p-4">
          <KillChainStrip events={events} />
        </div>

        <div className="flex-1 overflow-y-auto p-4">
          <StoryTimeline events={events} visibleCount={replay.index + 1} />
        </div>
      </div>
    </div>
  );
}
'use client';

import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Play, Pause, RotateCcw, Filter } from 'lucide-react';
import { useReplay } from '@/hooks/useReplay';
import { useUI } from '@/store/ui';
import { cn } from '@/lib/utils';

interface GraphToolbarProps {
  eventCount?: number;
  simulatedThreat?: boolean;
  onToggleSimulatedThreat?: () => void;
}

export function GraphToolbar({
  eventCount = 0,
  simulatedThreat = false,
  onToggleSimulatedThreat,
}: GraphToolbarProps) {
  const { playing, play, pause } = useReplay(eventCount);
  const activePathId = useUI((s) => s.activePathId);
  const setActivePath = useUI((s) => s.setActivePath);

  return (
    <div className="pointer-events-auto absolute left-4 top-4 z-10 flex items-center gap-2 rounded-lg border border-border bg-card/90 px-2 py-1.5 backdrop-blur">
      <Button
        variant="ghost"
        size="sm"
        className="h-7 gap-1.5"
        onClick={playing ? pause : play}
        disabled={eventCount === 0}
      >
        {playing ? <Pause className="size-3.5" /> : <Play className="size-3.5" />}
        {playing ? 'Pause replay' : 'Replay attack'}
      </Button>
      <div className="h-4 w-px bg-border" />
      <Button
        variant="ghost"
        size="sm"
        className="h-7 gap-1.5"
        onClick={() => setActivePath(null)}
        disabled={!activePathId}
      >
        <RotateCcw className="size-3.5" /> Clear path
      </Button>
      <div className="h-4 w-px bg-border" />
      <Badge variant="outline" className="gap-1 text-[10.5px]">
        <Filter className="size-3" /> Live
      </Badge>

      {onToggleSimulatedThreat && (
        <>
          <div className="h-4 w-px bg-border" />
          <Button
            variant={simulatedThreat ? 'destructive' : 'secondary'}
            size="sm"
            className={cn('h-7 gap-1.5 text-[11px] font-medium transition-all', simulatedThreat && 'animate-pulse shadow-[0_0_12px_rgba(239,68,68,0.5)]')}
            onClick={onToggleSimulatedThreat}
          >
            {simulatedThreat ? 'Threat Active (Click to Reset)' : 'Simulate Threat Action'}
          </Button>
        </>
      )}
    </div>
  );
}

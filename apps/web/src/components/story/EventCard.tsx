'use client';

import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { StoryEvent } from '@/types/domain';
import {  } from 'lucide-react';

const KIND_LABEL: Record<StoryEvent['kind'], string> = {
  'initial-access': 'Initial Access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege Esc.',
  'lateral-movement': 'Lateral Movement',
  collection: 'Collection',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
  response: 'Response',
};

export function EventCard({
  event,
  active,
  onClick,
}: {
  event: StoryEvent;
  active?: boolean;
  onClick?: () => void;
}) {
  const time = new Date(event.ts).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full rounded-lg border bg-card p-3 text-left transition-all',
        active
          ? 'border-primary/60 ring-2 ring-primary/30'
          : 'border-border hover:border-muted-foreground/40',
      )}
    >
      <div className="mb-1.5 flex items-center gap-2">
        <span className="font-mono text-[11px] text-muted-foreground">{time}</span>
        <Badge variant="outline" className="text-[10px] uppercase tracking-wide">
          {KIND_LABEL[event.kind]}
        </Badge>
        <span className="font-mono text-[10.5px] text-muted-foreground">{event.technique}</span>
        {event.inferred && (
          <Badge
            variant="outline"
            className="ml-auto gap-1 border-dashed text-[10px] text-muted-foreground"
          >
            <span className="size-1.5 rounded-full bg-primary inline-block mr-1" />Inferred
          </Badge>
        )}
      </div>
      <p className="text-[12.5px] leading-snug">{event.narrative}</p>
      <div className="mt-2 font-mono text-[10.5px] text-muted-foreground">
        node: {event.nodeId}
      </div>
    </button>
  );
}
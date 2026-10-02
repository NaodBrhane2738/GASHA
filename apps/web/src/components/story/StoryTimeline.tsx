'use client';

import { cn } from '@/lib/utils';
import type { StoryEvent } from '@/types/domain';
import { useUI } from '@/store/ui';
import { EventCard } from './EventCard';

export function StoryTimeline({
  events,
  visibleCount,
}: {
  events: StoryEvent[];
  visibleCount?: number;
}) {
  const selectedEventId = useUI((s) => s.selectedEventId);
  const setSelectedEvent = useUI((s) => s.setSelectedEvent);

  const visible = typeof visibleCount === 'number' ? events.slice(0, visibleCount) : events;

  return (
    <ol className="relative ml-2 border-l border-border pl-6">
      {visible.map((e, i) => (
        <li key={e.id} className={cn('relative', i === visible.length - 1 ? 'pb-0' : 'pb-4')}>
          <span
            className={cn(
              'absolute -left-[31px] top-3 size-3 rounded-full',
              e.inferred
                ? 'border-2 border-dashed border-muted-foreground bg-background'
                : 'bg-primary ring-4 ring-primary/15',
            )}
          />
          <EventCard
            event={e}
            active={selectedEventId === e.id}
            onClick={() => setSelectedEvent(e.id)}
          />
        </li>
      ))}
    </ol>
  );
}
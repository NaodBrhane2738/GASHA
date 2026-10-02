'use client';

import { useEffect } from 'react';
import { useUI } from '@/store/ui';

export function useReplay(totalEvents: number, intervalMs = 900) {
  const replaying = useUI((s) => s.replaying);
  const index = useUI((s) => s.replayIndex);
  const setReplayIndex = useUI((s) => s.setReplayIndex);
  const setReplaying = useUI((s) => s.setReplaying);

  useEffect(() => {
    if (!replaying) return;
    if (index >= totalEvents - 1) {
      const t = setTimeout(() => setReplaying(false), intervalMs);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setReplayIndex(index + 1), intervalMs);
    return () => clearTimeout(t);
  }, [replaying, index, totalEvents, intervalMs, setReplayIndex, setReplaying]);

  return {
    index,
    playing: replaying,
    play: () => setReplayIndex(0) || setReplaying(true),
    pause: () => setReplaying(false),
    seek: (i: number) => setReplayIndex(i),
  };
}
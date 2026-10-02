'use client';

import { useEffect, useRef, useState } from 'react';
import type { Detection } from '@/types/domain';

export function useEventStream(onEvent: (d: Detection) => void) {
  const cb = useRef(onEvent);
  cb.current = onEvent;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      // In dev, we poll the mock endpoint instead of opening SSE
      const t = setInterval(async () => {
        try {
          const res = await fetch('/api/detections/stream');
          if (!res.ok) return;
          const item = (await res.json()) as Detection;
          cb.current(item);
          setConnected(true);
        } catch {
          setConnected(false);
        }
      }, 4000);
      return () => clearInterval(t);
    }

    const base = process.env.NEXT_PUBLIC_API_URL ?? '';
    const es = new EventSource(`${base}/stream`, { withCredentials: true });
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (m) => {
      try {
        cb.current(JSON.parse(m.data));
      } catch {
        /* ignore malformed */
      }
    };
    return () => es.close();
  }, []);

  return { connected };
}
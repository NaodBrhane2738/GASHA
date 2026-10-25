'use client';

import { useEffect, useRef, useState } from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import { API_BASE, authHeaders } from '@/lib/api/client';
import { METRICS_WINDOW, socKeys } from './queries';
import type { Finding, MetricsSnapshot, MetricsTick, SocEvent, SocIncident } from '@/types/soc';

/** Applies one bus event to the React Query cache so every SOC view stays in sync. */
export function applySocEvent(qc: QueryClient, ev: SocEvent) {
  switch (ev.type) {
    case 'metrics.tick': {
      const tick = ev.data as MetricsTick;
      qc.setQueryData<MetricsSnapshot>(socKeys.metrics, (prev) => {
        if (!prev) return prev;
        const series = prev.series.filter((b) => b.ts !== tick.bucket.ts);
        series.push(tick.bucket);
        return {
          ...prev,
          series: series.slice(-METRICS_WINDOW),
          activeMitigations: tick.activeMitigations,
          totals: {
            ...prev.totals,
            ...Object.fromEntries(
              Object.entries(tick.stageCounts).map(([k, v]) => [`stage${k[0]}${k.slice(1).toLowerCase()}`, v]),
            ),
          },
        };
      });
      break;
    }
    case 'incident.updated': {
      const inc = ev.data as SocIncident;
      qc.setQueryData<SocIncident[]>(socKeys.incidents, (prev = []) => [
        inc,
        ...prev.filter((i) => i.id !== inc.id),
      ]);
      break;
    }
    case 'finding.created': {
      const f = ev.data as Finding;
      qc.setQueryData<Finding[]>(socKeys.findings, (prev = []) => [f, ...prev].slice(0, 200));
      break;
    }
    case 'policy.enforced':
    case 'mitigation.expired':
    case 'mitigation.released':
      qc.invalidateQueries({ queryKey: socKeys.metrics });
      break;
  }
}

function parseFrame(frame: string): SocEvent | null {
  let data = '';
  for (const line of frame.split('\n')) {
    if (line.startsWith('data:')) data += line.slice(5).trimStart();
  }
  if (!data) return null;
  try {
    return JSON.parse(data) as SocEvent;
  } catch {
    return null;
  }
}

/**
 * Subscribes to /soc/stream. Uses fetch + ReadableStream instead of EventSource so the
 * analyst token is sent in the Authorization header, never in the query string.
 */
export function useSocStream(onEvent?: (ev: SocEvent) => void) {
  const qc = useQueryClient();
  const cb = useRef(onEvent);
  cb.current = onEvent;
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const ctrl = new AbortController();
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const connect = async () => {
      try {
        const res = await fetch(`${API_BASE}/soc/stream`, {
          headers: { Accept: 'text/event-stream', ...authHeaders() },
          credentials: 'include',
          signal: ctrl.signal,
        });
        if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
        setConnected(true);
        attempt = 0;
        const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = '';
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let idx;
          while ((idx = buf.indexOf('\n\n')) >= 0) {
            const ev = parseFrame(buf.slice(0, idx));
            buf = buf.slice(idx + 2);
            if (ev) {
              applySocEvent(qc, ev);
              cb.current?.(ev);
            }
          }
        }
      } catch {
        if (ctrl.signal.aborted) return;
      }
      setConnected(false);
      if (ctrl.signal.aborted) return;
      attempt += 1;
      timer = setTimeout(connect, Math.min(30_000, 1000 * 2 ** attempt));
    };

    connect();
    return () => {
      ctrl.abort();
      if (timer) clearTimeout(timer);
    };
  }, [qc]);

  return { connected };
}

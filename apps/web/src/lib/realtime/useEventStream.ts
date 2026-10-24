'use client';

import { useEffect, useRef, useState } from 'react';
import type { Detection } from '@/types/domain';
import { getBaseApiUrl } from '@/lib/api/client';

export function useEventStream(onEvent: (d: Detection) => void) {
  const cb = useRef(onEvent);
  useEffect(() => {
    cb.current = onEvent;
  }, [onEvent]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: any = null;
    let destroyed = false;

    async function connect() {
      if (destroyed) return;
      try {
        const token = typeof window !== 'undefined' ? localStorage.getItem('gasha_token') : null;
        let ticket: string | null = null;

        const backendBase = getBaseApiUrl();

        // Try getting a short-lived ticket
        try {
          const ticketUrl = `${backendBase}/realtime/ticket`;
          const res = await fetch(ticketUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              ...(token ? { Authorization: `Bearer ${token}` } : {})
            }
          });
          if (res.ok) {
            const data = await res.json();
            ticket = data.ticket;
          }
        } catch {
          // Proceed with token query param if ticket issue fails
        }

        const wsUrlStr = backendBase.replace(/^http/, 'ws');
        const wsEndpoint = `${wsUrlStr}/realtime/ws?${ticket ? `ticket=${ticket}` : (token ? `token=${token}` : '')}`;

        ws = new WebSocket(wsEndpoint);

        ws.onopen = () => {
          if (destroyed) {
            ws?.close();
            return;
          }
          setConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            const raw = msg.data || msg.payload || msg;
            const ruleObj = typeof raw.rule === 'object' && raw.rule ? raw.rule : null;
            const ruleName = ruleObj ? (ruleObj.name || ruleObj.ruleId) : (raw.rule || 'Behavioral Detection');
            const item: Detection = {
              id: raw.id || `det-${Date.now()}`,
              ts: raw.timestamp || raw.ts || new Date().toISOString(),
              nodeId: raw.primaryAssetId || raw.nodeId || 'unknown',
              rule: ruleName,
              severity: (raw.severity || 'medium').toLowerCase() as any,
              technique: raw.metadata?.mitreTechniqueId || raw.technique || 'T1059',
              confidence: raw.confidence ?? 0.92,
              summary: raw.evidenceSummary || raw.summary || 'Live threat event observed'
            };
            cb.current(item);
          } catch {
            /* ignore non-json messages */
          }
        };

        ws.onclose = () => {
          setConnected(false);
          if (!destroyed) {
            timer = setTimeout(connect, 4000);
          }
        };

        ws.onerror = () => {
          setConnected(false);
          ws?.close();
        };
      } catch {
        setConnected(false);
        if (!destroyed) {
          timer = setTimeout(connect, 5000);
        }
      }
    }

    connect();

    return () => {
      destroyed = true;
      if (timer) clearTimeout(timer);
      if (ws) ws.close();
    };
  }, []);

  return { connected };
}

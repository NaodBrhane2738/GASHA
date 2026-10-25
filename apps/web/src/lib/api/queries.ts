'use client';

// Data hooks for every dashboard page. They read from the shared simulation (lib/sim) so all
// views describe the same incidents, responses and risk at the same moment.

import { useCallback, useMemo, useState } from 'react';
import { useSim, sendCommand } from '@/lib/sim/runtime';
import { BASE_TWIN } from '@/lib/sim/seed';
import { POLICY, type SimIncident, type SimState } from '@/lib/sim/engine';
import type { AttackPath, Detection, Incident, ResponseAction, RiskSnapshot, StoryEvent, TwinGraphData } from '@/types/domain';
import type { LifecycleStage } from '@/types/soc';

const useState$ = () => useSim((s) => s.state);

function result<T>(state: SimState | null, data: T | undefined) {
  return { data, isLoading: !state };
}

export function toIncident(i: SimIncident): Incident {
  return {
    id: i.id,
    title: i.title,
    severity: i.severity.toLowerCase() as Incident['severity'],
    status: i.status === 'OPEN' ? 'open' : i.status === 'MITIGATED' ? 'contained' : 'resolved',
    openedAt: i.openedAt,
    detectionIds: i.detectionIds,
    pathId: i.pathId,
    riskBefore: i.riskBefore,
    riskAfter: i.riskAfter,
    confidence: i.confidence,
  };
}

export function nodeStatus(state: SimState) {
  const attacked = new Set<string>();
  const contained = new Set<string>();
  for (const i of state.incidents) {
    if (i.status !== 'RESOLVED') i.nodeIds.forEach((n) => attacked.add(n));
    else if (i.contained) i.nodeIds.forEach((n) => contained.add(n));
  }
  return { attacked, contained };
}

export const useTwin = () => {
  const state = useState$();
  const data = useMemo<TwinGraphData | undefined>(() => {
    if (!state) return undefined;
    const { attacked, contained } = nodeStatus(state);
    return {
      updatedAt: new Date(state.now).toISOString(),
      edges: BASE_TWIN.edges,
      nodes: BASE_TWIN.nodes.map((n) => ({
        ...n,
        riskScore: attacked.has(n.id) ? Math.min(99, n.riskScore + 18) : contained.has(n.id) ? Math.round(n.riskScore * 0.6) : n.riskScore,
        metadata: { status: attacked.has(n.id) ? 'under-attack' : contained.has(n.id) ? 'contained' : 'normal' },
      })),
    };
  }, [state]);
  return result(state, data);
};

export const usePaths = () => {
  const state = useState$();
  const data = useMemo<AttackPath[] | undefined>(
    () => state?.paths.map((p) => (p.status === 'mitigated' ? { ...p, riskScore: Math.round(p.riskScore * 0.3) } : p)),
    [state],
  );
  return result(state, data);
};

export const useDetections = () => {
  const state = useState$();
  return result<Detection[]>(state, state?.detections);
};

export const useIncidents = () => {
  const state = useState$();
  const data = useMemo(() => state?.incidents.map(toIncident), [state]);
  return result(state, data);
};

export const useSimIncident = (id: string) => {
  const state = useState$();
  return result(state, state?.incidents.find((i) => i.id === id));
};

export const useIncident = (id: string) => {
  const { data: inc, isLoading } = useSimIncident(id);
  const data = useMemo(() => (inc ? toIncident(inc) : undefined), [inc]);
  return { data, isLoading };
};

export const useStory = (id: string) => {
  const { data: inc, isLoading } = useSimIncident(id);
  return { data: inc?.story as StoryEvent[] | undefined, isLoading };
};

export const useResponses = () => {
  const state = useState$();
  return result<ResponseAction[]>(state, state?.responses);
};

export const useRisk = () => {
  const state = useState$();
  return result<RiskSnapshot[]>(state, state?.risk);
};

function useCommand<T>(run: (id: string) => Promise<T>) {
  const [isPending, setPending] = useState(false);
  const mutateAsync = useCallback(
    async (id: string) => {
      setPending(true);
      try {
        return await run(id);
      } finally {
        setPending(false);
      }
    },
    [run],
  );
  return { mutateAsync, isPending };
}

export const useApproveResponse = () =>
  useCommand(useCallback((id: string) => sendCommand<ResponseAction | null>({ type: 'approve', id }), []));

export const useRejectResponse = () =>
  useCommand(useCallback((id: string) => sendCommand<ResponseAction | null>({ type: 'reject', id }), []));

export const useReleaseMitigation = () =>
  useCommand(useCallback((ip: string) => sendCommand({ type: 'release', ip }), []));

/** Everything the SOC page needs, derived in one place. */
export const useSocView = () => {
  const state = useState$();
  return useMemo(() => {
    if (!state) return null;
    const stageCounts: Record<LifecycleStage | 'RESOLVED', number> = { INGESTED: 0, DETECTED: 0, ENFORCED: 0, MITIGATED: 0, RESOLVED: 0 };
    for (const i of state.incidents) {
      for (const st of new Set(i.steps.map((s) => s.stage))) stageCounts[st] += 1;
      if (i.status === 'RESOLVED') stageCounts.RESOLVED += 1;
    }
    const topSources = Object.entries(state.rate)
      .map(([sourceKey, w]) => ({ sourceKey, requestsInWindow: w.filter((t) => t > state.now - POLICY.windowSeconds * 1000).length }))
      .filter((s) => s.requestsInWindow > 0)
      .sort((a, b) => b.requestsInWindow - a.requestsInWindow)
      .slice(0, 5);
    return {
      state,
      stageCounts,
      topSources,
      policy: POLICY,
      riskNow: state.risk[state.risk.length - 1]?.score ?? 0,
    };
  }, [state]);
};

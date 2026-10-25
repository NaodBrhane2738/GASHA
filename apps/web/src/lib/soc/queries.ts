'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api/client';
import type { Finding, FindingAnalysis, MetricsSnapshot, Mitigation, SocIncident } from '@/types/soc';

export const METRICS_WINDOW = 300;

export const socKeys = {
  metrics: ['soc', 'metrics'] as const,
  incidents: ['soc', 'incidents'] as const,
  findings: ['soc', 'findings'] as const,
  analysis: (id: string) => ['soc', 'analysis', id] as const,
};

export const useSocMetrics = () =>
  useQuery({
    queryKey: socKeys.metrics,
    queryFn: () => api<MetricsSnapshot>(`/soc/metrics?window=${METRICS_WINDOW}`),
    // The stream keeps this fresh; poll slowly as a fallback if it drops.
    refetchInterval: 30_000,
  });

export const useSocIncidents = () =>
  useQuery({ queryKey: socKeys.incidents, queryFn: () => api<SocIncident[]>('/soc/incidents?limit=100') });

export const useSocFindings = () =>
  useQuery({ queryKey: socKeys.findings, queryFn: () => api<Finding[]>('/soc/findings?limit=200') });

export const useFindingAnalysis = (id: string | null) =>
  useQuery({
    queryKey: socKeys.analysis(id ?? ''),
    queryFn: () => api<FindingAnalysis>(`/soc/findings/${id}/analysis`),
    enabled: !!id,
    staleTime: Infinity,
  });

export const useReleaseMitigation = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (sourceKey: string) =>
      api<Mitigation>(`/soc/mitigations/${encodeURIComponent(sourceKey)}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: socKeys.metrics });
      qc.invalidateQueries({ queryKey: socKeys.incidents });
    },
  });
};

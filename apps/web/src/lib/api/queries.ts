'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from './client';
import type {
  AttackPath,
  Detection,
  Incident,
  ResponseAction,
  RiskSnapshot,
  StoryEvent,
  TwinGraphData,
} from '@/types/domain';

export const qk = {
  twin: ['twin'] as const,
  paths: ['paths'] as const,
  detections: ['detections'] as const,
  incidents: ['incidents'] as const,
  incident: (id: string) => ['incident', id] as const,
  story: (id: string) => ['story', id] as const,
  responses: ['responses'] as const,
  risk: ['risk'] as const,
};

export const useTwin = () =>
  useQuery({ queryKey: qk.twin, queryFn: () => api<TwinGraphData>('/twin'), refetchInterval: 4000 });

export const usePaths = () =>
  useQuery({ queryKey: qk.paths, queryFn: () => api<AttackPath[]>('/attack-paths') });

export const useDetections = () =>
  useQuery({ queryKey: qk.detections, queryFn: () => api<Detection[]>('/detections'), refetchInterval: 2000 });

export const useIncidents = () =>
  useQuery({ queryKey: qk.incidents, queryFn: () => api<Incident[]>('/incidents'), refetchInterval: 2000 });

export const useIncident = (id: string) =>
  useQuery({
    queryKey: qk.incident(id),
    queryFn: () => api<Incident>(`/incidents/${id}`),
    enabled: !!id,
  });

export const useStory = (id: string) =>
  useQuery({
    queryKey: qk.story(id),
    queryFn: () => api<StoryEvent[]>(`/incidents/${id}/story`),
    enabled: !!id,
  });

export const useResponses = () =>
  useQuery({ queryKey: qk.responses, queryFn: () => api<ResponseAction[]>('/responses'), refetchInterval: 2000 });

export const useRisk = () =>
  useQuery({ queryKey: qk.risk, queryFn: () => api<RiskSnapshot[]>('/risk'), refetchInterval: 3000 });

export const useApproveResponse = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<ResponseAction>(`/responses/${id}/approve`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.responses });
      qc.invalidateQueries({ queryKey: qk.twin });
      qc.invalidateQueries({ queryKey: qk.paths });
      qc.invalidateQueries({ queryKey: qk.risk });
    },
  });
};

export const useRejectResponse = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api<ResponseAction>(`/responses/${id}/reject`, { method: 'POST' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.responses }),
  });
};
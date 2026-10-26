'use client';

import { create } from 'zustand';

export interface ArchivedIncidentRecord {
  id: string;
  title: string;
  severity: string;
  status: string;
  openedAt: string;
  createdAt?: string;
  attackerIp?: string;
  primaryAffectedAssetId?: string;
  cveId?: string;
  technique?: string;
  summary: string;
  description: string;
  riskBefore: number;
  riskAfter: number;
  detectionIds?: string[];
}

interface UIState {
  activePathId: string | null;
  selectedNodeId: string | null;
  selectedEventId: string | null;
  selectedIncidentId: string | null;
  replaying: boolean;
  replayIndex: number;
  blockedIps: string[];
  blockedAssetIds: string[];
  archivedIncidents: ArchivedIncidentRecord[];
  setActivePath: (id: string | null) => void;
  setSelectedNode: (id: string | null) => void;
  setSelectedEvent: (id: string | null) => void;
  setSelectedIncident: (id: string | null) => void;
  setReplaying: (v: boolean) => void;
  setReplayIndex: (i: number) => void;
  blockThreat: (ip: string, assetId?: string, incidentRecord?: ArchivedIncidentRecord) => void;
  unblockAll: () => void;
  reset: () => void;
}

const getStoredList = (key: string): any[] => {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
};

export const useUI = create<UIState>((set) => ({
  activePathId: null,
  selectedNodeId: null,
  selectedEventId: null,
  selectedIncidentId: null,
  replaying: false,
  replayIndex: 0,
  blockedIps: getStoredList('gasha_blocked_ips'),
  blockedAssetIds: getStoredList('gasha_blocked_assets'),
  archivedIncidents: getStoredList('gasha_archived_incidents'),

  setActivePath: (id) => set({ activePathId: id }),
  setSelectedNode: (id) => set({ selectedNodeId: id }),
  setSelectedEvent: (id) => set({ selectedEventId: id }),
  setSelectedIncident: (id) => set({ selectedIncidentId: id }),
  setReplaying: (v) => set({ replaying: v }),
  setReplayIndex: (i) => set({ replayIndex: i }),

  blockThreat: (ip: string, assetId?: string, incidentRecord?: ArchivedIncidentRecord) => {
    set((state) => {
      const nextIps = Array.from(new Set([...state.blockedIps, ip]));
      const nextAssets = assetId ? Array.from(new Set([...state.blockedAssetIds, assetId])) : state.blockedAssetIds;
      
      let nextArchived = [...state.archivedIncidents];
      if (incidentRecord) {
        nextArchived = [incidentRecord, ...nextArchived.filter((i) => i.id !== incidentRecord.id)];
      }

      if (typeof window !== 'undefined') {
        try {
          localStorage.setItem('gasha_blocked_ips', JSON.stringify(nextIps));
          localStorage.setItem('gasha_blocked_assets', JSON.stringify(nextAssets));
          localStorage.setItem('gasha_archived_incidents', JSON.stringify(nextArchived));
        } catch {
          // ignore localStorage errors in sandboxed environments
        }
      }

      return {
        blockedIps: nextIps,
        blockedAssetIds: nextAssets,
        archivedIncidents: nextArchived,
      };
    });
  },

  unblockAll: () => {
    if (typeof window !== 'undefined') {
      try {
        localStorage.removeItem('gasha_blocked_ips');
        localStorage.removeItem('gasha_blocked_assets');
        localStorage.removeItem('gasha_archived_incidents');
      } catch {
        // ignore
      }
    }
    set({
      blockedIps: [],
      blockedAssetIds: [],
      archivedIncidents: [],
    });
  },

  reset: () =>
    set({
      activePathId: null,
      selectedNodeId: null,
      selectedEventId: null,
      selectedIncidentId: null,
      replaying: false,
      replayIndex: 0,
    }),
}));

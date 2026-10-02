'use client';

import { create } from 'zustand';

interface UIState {
  activePathId: string | null;
  selectedNodeId: string | null;
  selectedEventId: string | null;
  selectedIncidentId: string | null;
  replaying: boolean;
  replayIndex: number;
  setActivePath: (id: string | null) => void;
  setSelectedNode: (id: string | null) => void;
  setSelectedEvent: (id: string | null) => void;
  setSelectedIncident: (id: string | null) => void;
  setReplaying: (v: boolean) => void;
  setReplayIndex: (i: number) => void;
  reset: () => void;
}

export const useUI = create<UIState>((set) => ({
  activePathId: null,
  selectedNodeId: null,
  selectedEventId: null,
  selectedIncidentId: null,
  replaying: false,
  replayIndex: 0,
  setActivePath: (id) => set({ activePathId: id }),
  setSelectedNode: (id) => set({ selectedNodeId: id }),
  setSelectedEvent: (id) => set({ selectedEventId: id }),
  setSelectedIncident: (id) => set({ selectedIncidentId: id }),
  setReplaying: (v) => set({ replaying: v }),
  setReplayIndex: (i) => set({ replayIndex: i }),
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
'use client';

import { create } from 'zustand';
import type { PolicyProblem } from '@/types/soc';

export interface PolicyNotice {
  status: 429 | 423 | 413;
  title: string;
  detail: string;
  ruleId?: string | null;
  incidentId?: string | null;
  /** epoch ms when the client may retry; null when unknown */
  retryAt: number | null;
  receivedAt: number;
}

interface PolicyState {
  notice: PolicyNotice | null;
  report: (status: number, problem: Partial<PolicyProblem>, retryAfterHeader?: string | null) => void;
  dismiss: () => void;
}

export const isPolicyStatus = (s: number): s is 429 | 423 | 413 => s === 429 || s === 423 || s === 413;

export const usePolicy = create<PolicyState>((set) => ({
  notice: null,
  report: (status, problem, retryAfterHeader) => {
    if (!isPolicyStatus(status)) return;
    const secs = Number(retryAfterHeader ?? problem.retryAfter);
    const now = Date.now();
    set({
      notice: {
        status,
        title: problem.title ?? (status === 429 ? 'Too Many Requests' : status === 423 ? 'Resource Locked' : 'Content Too Large'),
        detail: problem.detail ?? '',
        ruleId: problem.ruleId,
        incidentId: problem.incidentId,
        retryAt: Number.isFinite(secs) && secs > 0 ? now + secs * 1000 : null,
        receivedAt: now,
      },
    });
  },
  dismiss: () => set({ notice: null }),
}));

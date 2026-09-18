/**
 * ==============================================================================
 * FILE: packages/ui/components/index.tsx
 * ROLE / OWNERSHIP: Frontend Engineers / UI System Designers
 * OBJECTIVE: Provide primitive and cybersecurity-specific UI widgets.
 * TOOLS & LIBRARIES: React 18+, Tailwind CSS, clsx / tailwind-merge
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - SeverityBadge: Color-coded badge for LOW, MEDIUM, HIGH, CRITICAL.
 *   - RiskDial: Circular visual gauge displaying 0-100 risk score with trend indicators.
 *   - AssetIconBadge: Icon badge indicating asset type (API, Database, Lambda, Vercel).
 *   - ContainmentStatusTag: Badge showing NORMAL, ACTIVE_DEFENSE, LOCKDOWN.
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Consistent UI tokens across dashboard, digital twin, and investigation views.
 * ==============================================================================
 */

import React from 'react';

export interface SeverityBadgeProps {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const colorMap = {
    LOW: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    CRITICAL: 'bg-rose-500/10 text-rose-400 border-rose-500/20'
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colorMap[severity]}`}>
      {severity}
    </span>
  );
};

export interface RiskDialProps {
  score: number;
}

export const RiskDial: React.FC<RiskDialProps> = ({ score }) => {
  return (
    <div className="flex flex-col items-center justify-center p-4 bg-slate-900 border border-slate-800 rounded-xl">
      <div className="text-3xl font-bold text-white">{score}</div>
      <div className="text-xs text-slate-400 mt-1 uppercase tracking-wider">Environment Risk</div>
    </div>
  );
};

/**
 * ==============================================================================
 * FILE: apps/web/app/dashboard/page.tsx
 * ROLE / OWNERSHIP: Frontend Engineers (Lead Frontend Developer)
 * OBJECTIVE: Main security command center dashboard page.
 * TOOLS & LIBRARIES: Next.js App Router, React 18, Tailwind CSS, Lucide Icons, @gasha/ui
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - Environment Health & Containment Status Banner (NORMAL / ACTIVE_DEFENSE)
 *   - Overall Environment Risk Score Dial & Trend Indicators
 *   - Critical Assets at Risk Grid
 *   - Active Incidents Real-Time Ticker
 *   - Quick navigation links to Digital Twin, Attack Paths, and Investigation Views
 * EXPECTED RESULTS / BEHAVIOR:
 *   - High-impact visual landing page displaying real-time environment security state.
 * ==============================================================================
 */

import React from 'react';
import { SeverityBadge, RiskDial } from '@gasha/ui';

export default function DashboardPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8">
      {/* Header Bar */}
      <header className="flex items-center justify-between pb-6 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">GASHA Command Center</h1>
          <p className="text-sm text-slate-400 mt-1">Graph-Adaptive Security & Hardening Architecture</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            SYSTEM ONLINE
          </span>
        </div>
      </header>

      {/* Main Metrics Grid */}
      <section className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-8">
        <RiskDial score={42} />
        
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="text-sm text-slate-400 font-medium">Active Incidents</div>
          <div className="text-3xl font-bold text-rose-400 mt-2">1</div>
          <div className="text-xs text-rose-500/80 mt-1">1 High Severity</div>
        </div>

        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="text-sm text-slate-400 font-medium">Critical Crown Jewels</div>
          <div className="text-3xl font-bold text-amber-400 mt-2">2</div>
          <div className="text-xs text-slate-400 mt-1">Tier-0 Assets Monitored</div>
        </div>

        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="text-sm text-slate-400 font-medium">Active Attack Paths</div>
          <div className="text-3xl font-bold text-orange-400 mt-2">1</div>
          <div className="text-xs text-orange-400/80 mt-1">Targeting Customer DB</div>
        </div>
      </section>

      {/* Incident Ticker & Quick Links */}
      <section className="mt-8 p-6 bg-slate-900 border border-slate-800 rounded-xl">
        <h2 className="text-lg font-semibold text-white mb-4">Active Threat Stream</h2>
        <div className="p-4 bg-slate-950/60 border border-slate-800/80 rounded-lg flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <SeverityBadge severity="HIGH" />
              <span className="font-medium text-slate-200">Suspicious Authentication & Database Probe</span>
            </div>
            <p className="text-xs text-slate-400 mt-1">Source IP: 198.51.100.42 • Target: auth-service</p>
          </div>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition-colors">
            Open Investigation
          </button>
        </div>
      </section>
    </main>
  );
}

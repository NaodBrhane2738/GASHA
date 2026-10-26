'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Radar,
  Route,
  Activity,
  ShieldAlert,
  GitMerge,
  BookOpen,
  Gauge,
  Shield,
  Database,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { usePaths, useDetections, useIncidents, useResponses, useTwin, useRisk } from '@/lib/api/queries';

const STAGES = [
  { key: 'twin', label: 'Discover', href: '/twin', icon: Radar, metricKey: 'nodes', description: 'Digital Twin & Topology' },
  { key: 'paths', label: 'Model', href: '/paths', icon: Route, metricKey: 'paths', description: 'Attack Paths & Graph' },
  { key: 'telemetry', label: 'Observe', href: '/telemetry', icon: Activity, metricKey: 'events', description: 'Live Telemetry & Incursions' },
  { key: 'detections', label: 'Detect', href: '/detections', icon: ShieldAlert, metricKey: 'dets', description: 'Correlated Rule Detections' },
  { key: 'incidents', label: 'Correlate', href: '/incidents', icon: GitMerge, metricKey: 'incs', description: 'Active Security Incidents' },
  { key: 'reconstruct', label: 'Reconstruct', href: '/incidents', icon: BookOpen, metricKey: 'incs', description: 'Attack Story Timeline' },
  { key: 'risk', label: 'Measure', href: '/risk', icon: Gauge, metricKey: 'risk', description: 'System Risk Exposure' },
  { key: 'response', label: 'Respond', href: '/response', icon: Shield, metricKey: 'acts', description: 'Quarantine & Containment' },
  { key: 'database', label: 'Database', href: '/database', icon: Database, metricKey: '', description: 'Verified Containment Ledger' },
] as const;

interface LoopRailProps {
  open?: boolean;
  onClose?: () => void;
}

export function LoopRail({ open = false, onClose = () => {} }: LoopRailProps) {
  const pathname = usePathname();
  const { data: paths } = usePaths();
  const { data: dets } = useDetections();
  const { data: incs } = useIncidents();
  const { data: resps } = useResponses();
  const { data: twin } = useTwin();
  const { data: riskHist } = useRisk();
  const latestRisk = riskHist?.[riskHist.length - 1];

  // Auto-close drawer on route navigation
  useEffect(() => {
    onClose();
  }, [pathname]);

  // Close on Escape key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (open) {
      window.addEventListener('keydown', handleKeyDown);
      return () => window.removeEventListener('keydown', handleKeyDown);
    }
  }, [open, onClose]);

  const metrics: Record<string, number> = {
    nodes: twin?.nodes?.length ?? 0,
    paths: paths?.filter((p) => String(p.status).toLowerCase() === 'open').length ?? 0,
    events: dets?.length ?? 0,
    dets: dets?.filter((d) => {
      const s = String(d.severity).toLowerCase();
      return s === 'high' || s === 'critical';
    }).length ?? 0,
    incs: incs?.filter((i) => {
      const s = String(i.status).toLowerCase();
      return s === 'open' || s === 'active' || s === 'investigating';
    }).length ?? 0,
    risk: latestRisk?.score ?? 35,
    acts: resps?.filter((r) => {
      const s = String(r.state ?? (r as any).status ?? '').toLowerCase();
      return s === 'proposed';
    }).length ?? 0,
    enforced: resps?.filter((r) => {
      const s = String(r.state ?? (r as any).status ?? '').toLowerCase();
      return s === 'done' || s === 'succeeded' || s === 'completed';
    }).length ?? 0,
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className={cn(
          'fixed inset-0 z-50 bg-black/60 backdrop-blur-sm transition-opacity duration-200',
          open ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'
        )}
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Side Navigation Drawer */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-72 sm:w-80 border-r border-border bg-card/95 backdrop-blur-xl shadow-2xl flex flex-col transition-transform duration-300 ease-in-out',
          open ? 'translate-x-0' : '-translate-x-full'
        )}
        aria-label="Operation Lifecycle Drawer"
      >
        {/* Drawer Header */}
        <div className="flex items-center justify-between border-b border-border p-3.5 bg-secondary/30">
          <div className="flex items-center gap-2.5">
            <div className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary border border-primary/30">
              <span className="text-[12px] font-bold">G</span>
            </div>
            <div>
              <div className="text-[13px] font-bold text-foreground">Operation Loop</div>
              <div className="text-[10px] text-muted-foreground">9 Continuous Lifecycle Stages</div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="flex size-7 items-center justify-center rounded-md text-muted-foreground hover:bg-secondary hover:text-foreground transition-colors"
            aria-label="Close Operations Drawer"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Drawer Stages List */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-1.5" aria-label="Security Lifecycle Stages">
          {STAGES.map((s, i) => {
            const Icon = s.icon;
            const active = pathname.startsWith(s.href) && (i === 0 || s.key !== 'twin');
            const metric = metrics[s.metricKey] ?? 0;
            return (
              <Link
                key={`${s.key}-${i}`}
                href={s.href}
                onClick={onClose}
                className={cn(
                  'group flex items-center justify-between rounded-lg p-2.5 text-[12.5px] transition-all border',
                  active
                    ? 'bg-white/15 text-white border-white/50 font-semibold shadow-sm shadow-white/10 hover:bg-white/20 hover:text-white hover:border-white/70'
                    : 'text-muted-foreground hover:bg-white/10 hover:text-white hover:border-white/30 border-transparent',
                )}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <Icon className={cn('size-4 shrink-0 transition-colors', active ? 'text-white' : 'group-hover:text-white')} />
                  <div className="flex flex-col text-left truncate">
                    <span className="truncate leading-tight font-medium">{s.label}</span>
                    <span className={cn('text-[10px] truncate', active ? 'text-white/80' : 'text-muted-foreground group-hover:text-white/70')}>
                      {s.description}
                    </span>
                  </div>
                </div>

                {metric > 0 && (
                  <span
                    className={cn(
                      'rounded px-2 py-0.5 text-[10px] font-mono shrink-0 transition-colors ml-2',
                      active
                        ? 'bg-white/25 text-white font-bold border border-white/25'
                        : 'bg-secondary text-muted-foreground group-hover:bg-white/15 group-hover:text-white',
                    )}
                  >
                    {metric}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Drawer Footer */}
        <div className="border-t border-border p-3 bg-secondary/20 text-[10.5px] text-muted-foreground flex items-center justify-between font-mono">
          <span>env-prod · active</span>
          <span className="text-[10px] text-muted-foreground/80">Esc to close</span>
        </div>
      </aside>
    </>
  );
}

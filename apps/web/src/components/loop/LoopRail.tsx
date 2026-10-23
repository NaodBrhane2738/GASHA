'use client';

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
  Zap,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { usePaths, useDetections, useIncidents, useResponses, useTwin, useRisk } from '@/lib/api/queries';

const STAGES = [
  { key: 'twin', label: 'Discover', href: '/twin', icon: Radar, metricKey: 'nodes' },
  { key: 'paths', label: 'Model', href: '/paths', icon: Route, metricKey: 'paths' },
  { key: 'telemetry', label: 'Observe', href: '/telemetry', icon: Activity, metricKey: 'events' },
  { key: 'detections', label: 'Detect', href: '/detections', icon: ShieldAlert, metricKey: 'dets' },
  { key: 'incidents', label: 'Correlate', href: '/incidents', icon: GitMerge, metricKey: 'incs' },
  { key: 'incidents', label: 'Reconstruct', href: '/incidents', icon: BookOpen, metricKey: 'incs' },
  { key: 'risk', label: 'Measure', href: '/risk', icon: Gauge, metricKey: 'risk' },
  { key: 'response', label: 'Respond', href: '/response', icon: Zap, metricKey: 'acts' },
] as const;

export function LoopRail() {
  const pathname = usePathname();
  const { data: paths } = usePaths();
  const { data: dets } = useDetections();
  const { data: incs } = useIncidents();
  const { data: resps } = useResponses();
  const { data: twin } = useTwin();
  const { data: riskHist } = useRisk();
  const latestRisk = riskHist?.[riskHist.length - 1];

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
  };

  return (
    <div className="flex items-center gap-1 overflow-x-auto border-b border-border bg-card/50 px-4 py-2">
      {STAGES.map((s, i) => {
        const Icon = s.icon;
        const active = pathname.startsWith(s.href) && (i === 0 || s.key !== 'twin');
        const metric = metrics[s.metricKey] ?? 0;
        return (
          <div key={`${s.key}-${i}`} className="flex items-center gap-1">
            <Link
              href={s.href}
              className={cn(
                'group flex items-center gap-2 rounded-md px-3 py-1.5 text-[12px] transition-colors',
                active
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-secondary hover:text-foreground',
              )}
            >
              <Icon className="size-3.5" />
              <span className="font-medium">{s.label}</span>
              {metric > 0 && (
                <span
                  className={cn(
                    'rounded px-1.5 py-0.5 text-[10px] font-mono',
                    active ? 'bg-primary/20 text-primary' : 'bg-secondary text-muted-foreground',
                  )}
                >
                  {metric}
                </span>
              )}
            </Link>
            {i < STAGES.length - 1 && (
              <span className="text-muted-foreground/40">→</span>
            )}
          </div>
        );
      })}
    </div>
  );
}
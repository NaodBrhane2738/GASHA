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
  MonitorDot,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { usePaths, useDetections, useIncidents, useResponses, useRisk } from '@/lib/api/queries';
import { useSim } from '@/lib/sim/runtime';

const STAGES = [
  { key: 'soc', label: 'SOC', href: '/soc', icon: MonitorDot, metricKey: 'mits' },
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
  const { data: risk } = useRisk();
  const requests = useSim((s) => s.state?.requests.length ?? 0);
  const mits = useSim((s) => s.state?.mitigations.length ?? 0);

  const metrics: Record<string, number> = {
    mits,
    nodes: 10,
    paths: paths?.filter((p) => p.status === 'open').length ?? 0,
    events: requests,
    dets: dets?.filter((d) => d.severity === 'high' || d.severity === 'critical').length ?? 0,
    incs: incs?.filter((i) => i.status !== 'resolved').length ?? 0,
    risk: risk?.[risk.length - 1]?.score ?? 0,
    acts: resps?.filter((r) => r.state === 'proposed').length ?? 0,
  };

  return (
    <nav aria-label="Defense loop" className="flex items-center gap-1 overflow-x-auto border-b border-border bg-card/50 px-3 py-2 sm:px-4">
      {STAGES.map((s, i) => {
        const Icon = s.icon;
        const active = pathname.startsWith(s.href) && !(s.label === 'Reconstruct' && !pathname.startsWith('/incidents/'))
          && !(s.label === 'Correlate' && pathname.startsWith('/incidents/'));
        const metric = metrics[s.metricKey] ?? 0;
        const href = s.label === 'Reconstruct' && incs?.[0] ? `/incidents/${incs[0].id}` : s.href;
        return (
          <div key={`${s.key}-${i}`} className="flex items-center gap-1">
            <Link
              href={href}
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
    </nav>
  );
}

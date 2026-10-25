'use client';

import { useState, useMemo } from 'react';
import { useDetections, useIncidents, useTwin } from '@/lib/api/queries';
import { useEventStream } from '@/lib/realtime/useEventStream';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SEVERITY_TOKEN } from '@/lib/graph/nodeMeta';
import { resolveIncidentDossier, type DetailedIncidentDossier } from '@/lib/intelligence/cveMapping';
import { IncidentDossierModal } from '@/components/telemetry/IncidentDossierModal';
import {
  ShieldAlert,
  Search,
  Filter,
  Bug,
  Activity,
  ArrowRight,
  Flame,
  Radio,
  ExternalLink,
} from 'lucide-react';
import type { Detection } from '@/types/domain';
import { cn } from '@/lib/utils';

export default function TelemetryPage() {
  const { data: initial } = useDetections();
  const { data: incidents } = useIncidents();
  const { data: twin } = useTwin();

  const [live, setLive] = useState<Detection[]>([]);
  const { connected } = useEventStream((d) =>
    setLive((prev) => [d, ...prev].slice(0, 50)),
  );

  const [searchQuery, setSearchQuery] = useState('');
  const [filterCategory, setFilterCategory] = useState<'all' | 'critical' | 'ssrf' | 'sqli' | 'auth'>('all');
  const [selectedDossier, setSelectedDossier] = useState<DetailedIncidentDossier | null>(null);

  // Combine live stream with initial API detections, removing duplicates by ID
  const allDetections = useMemo(() => {
    const combined = [...live, ...(initial ?? [])];
    const seen = new Set<string>();
    const unique: Detection[] = [];
    for (const d of combined) {
      if (!seen.has(d.id)) {
        seen.add(d.id);
        unique.push(d);
      }
    }
    return unique.slice(0, 100);
  }, [live, initial]);

  // Enrich detections with CVE intelligence and incident dossier
  const dossiers = useMemo(() => {
    const incList = incidents ?? [];
    const nodeList = twin?.nodes ?? [];
    return allDetections.map((d) => resolveIncidentDossier(d, incList, nodeList));
  }, [allDetections, incidents, twin]);

  // Filter dossiers
  const filtered = useMemo(() => {
    return dossiers.filter((item) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        item.cve.id.toLowerCase().includes(q) ||
        item.mitre.techniqueId.toLowerCase().includes(q) ||
        item.targetAsset.label.toLowerCase().includes(q) ||
        item.attacker.ip.includes(q) ||
        item.summary.toLowerCase().includes(q) ||
        item.title.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      if (filterCategory === 'critical') {
        return item.severity === 'critical' || item.severity === 'high';
      }
      if (filterCategory === 'ssrf') {
        return item.summary.toLowerCase().includes('ssrf') || item.attacker.targetPath?.includes('fetch-url');
      }
      if (filterCategory === 'sqli') {
        return item.summary.toLowerCase().includes('sql') || item.cve.id.includes('48788');
      }
      if (filterCategory === 'auth') {
        return item.summary.toLowerCase().includes('auth') || item.mitre.techniqueId === 'T1110';
      }
      return true;
    });
  }, [dossiers, searchQuery, filterCategory]);

  return (
    <div className="flex h-[calc(100vh-100px)] flex-col p-4 space-y-3 overflow-hidden">
      {/* Top Header & Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0">
        <div>
          <h2 className="text-[14px] font-bold text-foreground flex items-center gap-2">
            <Activity className="size-4 text-primary" />
            Live Telemetry & CVE Vulnerability Observation
          </h2>
          <p className="text-[11.5px] text-muted-foreground">
            Correlated forensic telemetry events with real-time CVE mapping & incident dossiers. Click any observation to inspect full incident details.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Badge variant="outline" className="font-mono text-[11px] border-primary/30 text-primary">
            {filtered.length} Events Observed
          </Badge>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2.5 shrink-0 bg-card/60 border border-border p-2 rounded-lg backdrop-blur">
        <div className="relative flex-1 min-w-[260px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by CVE (e.g. CVE-2023-34362), MITRE technique, IP, asset, or keyword..."
            className="w-full rounded-md border border-border bg-secondary/50 py-1.5 pl-8 pr-3 text-[12px] placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary font-mono"
          />
        </div>

        {/* Filter Chips */}
        <div className="flex items-center gap-1.5 text-[11.5px]">
          <Button
            variant={filterCategory === 'all' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setFilterCategory('all')}
            className={cn('h-7 text-[11px]', filterCategory === 'all' && 'font-bold border border-border')}
          >
            All Observations
          </Button>
          <Button
            variant={filterCategory === 'critical' ? 'destructive' : 'ghost'}
            size="sm"
            onClick={() => setFilterCategory('critical')}
            className={cn('h-7 text-[11px]', filterCategory === 'critical' && 'font-bold')}
          >
            <Flame className="size-3 mr-1" /> Critical & High
          </Button>
          <Button
            variant={filterCategory === 'ssrf' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setFilterCategory('ssrf')}
            className={cn('h-7 text-[11px]', filterCategory === 'ssrf' && 'font-bold border border-border')}
          >
            SSRF Incursions
          </Button>
          <Button
            variant={filterCategory === 'sqli' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setFilterCategory('sqli')}
            className={cn('h-7 text-[11px]', filterCategory === 'sqli' && 'font-bold border border-border')}
          >
            SQL Injections
          </Button>
          <Button
            variant={filterCategory === 'auth' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setFilterCategory('auth')}
            className={cn('h-7 text-[11px]', filterCategory === 'auth' && 'font-bold border border-border')}
          >
            Brute Force
          </Button>
        </div>
      </div>

      {/* Main Telemetry & Observation Table */}
      <Card className="flex-1 overflow-hidden border-border bg-card shadow-sm flex flex-col">
        {/* Table Header */}
        <div className="grid grid-cols-[75px_80px_130px_90px_140px_1fr_65px_110px] items-center gap-3 border-b border-border bg-secondary/40 px-4 py-2.5 text-[11px] font-semibold text-muted-foreground">
          <span>TIME</span>
          <span>SEVERITY</span>
          <span>MAPPED CVE</span>
          <span>TECHNIQUE</span>
          <span>TARGET ASSET</span>
          <span>OBSERVED INCURSION & FORENSIC EVIDENCE</span>
          <span>CONFIDENCE</span>
          <span className="text-right">DETAILS</span>
        </div>

        {/* Scrollable Rows */}
        <div className="flex-1 overflow-y-auto divide-y divide-border">
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-12 text-center text-muted-foreground">
              <ShieldAlert className="size-8 text-muted-foreground/50 mb-2" />
              <div className="text-[13px] font-semibold">No telemetry events match query</div>
              <div className="text-[11.5px] mt-0.5">Try broadening your search or resetting category filters.</div>
            </div>
          ) : (
            filtered.map((item) => (
              <div
                key={item.id}
                onClick={() => setSelectedDossier(item)}
                className="group grid grid-cols-[75px_80px_130px_90px_140px_1fr_65px_110px] items-center gap-3 px-4 py-2.5 text-[12px] cursor-pointer transition-all hover:bg-primary/5 hover:border-l-2 hover:border-l-primary"
              >
                {/* Time */}
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>

                {/* Severity */}
                <span>
                  <span
                    className="inline-block rounded px-1.5 py-0.5 text-center text-[10.5px] font-bold uppercase tracking-wider font-mono"
                    style={{
                      background: `${SEVERITY_TOKEN[item.severity]}25`,
                      color: SEVERITY_TOKEN[item.severity],
                    }}
                  >
                    {item.severity}
                  </span>
                </span>

                {/* Mapped CVE with CVSS */}
                <div className="flex items-center gap-1.5">
                  <Badge
                    variant="outline"
                    className="font-mono text-[10px] border-red-500/30 text-red-400 bg-red-500/10 font-bold group-hover:border-red-500/60"
                  >
                    {item.cve.id}
                  </Badge>
                </div>

                {/* Technique */}
                <span className="font-mono text-[11px] text-muted-foreground font-semibold">
                  {item.mitre.techniqueId}
                </span>

                {/* Target Asset */}
                <div className="truncate">
                  <div className="truncate font-medium text-foreground text-[11.5px]">
                    {item.targetAsset.label}
                  </div>
                  <div className="font-mono text-[9.5px] uppercase text-muted-foreground">
                    {item.targetAsset.id}
                  </div>
                </div>

                {/* Summary */}
                <span className="truncate text-muted-foreground group-hover:text-foreground text-[11.5px]">
                  {item.summary}
                </span>

                {/* Confidence */}
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  {(item.telemetryEvidence.confidence * 100).toFixed(0)}%
                </span>

                {/* Action button */}
                <div className="text-right">
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-primary opacity-80 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all">
                    Inspect <ArrowRight className="size-3" />
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </Card>

      {/* Full Incident & CVE Intelligence Dossier Modal */}
      {selectedDossier && (
        <IncidentDossierModal
          dossier={selectedDossier}
          onClose={() => setSelectedDossier(null)}
        />
      )}
    </div>
  );
}

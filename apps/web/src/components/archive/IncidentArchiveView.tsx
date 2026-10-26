'use client';

import { useState, useMemo, useEffect } from 'react';
import { useUI } from '@/store/ui';
import Link from 'next/link';
import type { Incident } from '@/types/domain';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Calendar,
  AlertTriangle,
  ShieldCheck,
  Search,
  ChevronRight,
  ChevronDown,
  ArrowLeft,
  Activity,
  BookOpen,
  Lock,
  Database,
  ExternalLink,
  Info,
  Hash,
} from 'lucide-react';

interface IncidentArchiveViewProps {
  incidents?: Incident[];
  onSelectIncident?: (incident: Incident) => void;
  className?: string;
  initialFolderDate?: string | null;
  initialSelectedIncidentId?: string | null;
}

// Fallback baseline critical archive records across dates to ensure rich archive folders
const FALLBACK_ARCHIVED_INCIDENTS: Incident[] = [
  {
    id: 'inc-4f3e5cf1',
    title: 'Adversary SSRF & Cloud Metadata Incursion',
    severity: 'critical',
    status: 'contained',
    openedAt: '2026-10-26T08:00:00Z',
    createdAt: '2026-10-26T08:00:00Z',
    detectionIds: ['det-ssrf-1', 'det-ssrf-2'],
    pathId: 'path-cloud-pivot',
    confidence: 0.98,
    riskBefore: 99,
    riskAfter: 18,
    primaryAffectedAssetId: 'api-gateway',
    relatedAssetIds: ['auth-svc', 'nexus-target'],
    cveId: 'CVE-2023-34362',
    technique: 'T1190 · Exploit Public-Facing App',
    summary: 'Adversary at IP 198.51.100.101 executing Server-Side Request Forgery probes targeting internal cloud metadata (169.254.169.254).',
    description: `Adversary originating from external IP 198.51.100.101 executed high-velocity Server-Side Request Forgery (SSRF) probes targeting internal cloud instance metadata service (http://169.254.169.254/latest/meta-data/) via unvalidated redirect endpoints on the API Gateway.

The attacker attempted to extract IAM temporary security credentials and pivot into database clusters. Automated telemetry detection engines intercepted the metadata exfiltration probe within 140ms, proposed an immediate perimeter firewall blocklist containment order, and transitioned the asset into an isolated secure state. The threat is fully neutralized and contained.`,
  },
  {
    id: 'inc-20261026-02',
    title: 'Critical SQL Injection Remote Execution Probe',
    severity: 'critical',
    status: 'contained',
    openedAt: '2026-10-26T06:15:00Z',
    createdAt: '2026-10-26T06:15:00Z',
    detectionIds: ['det-sqli-1', 'det-sqli-2'],
    pathId: 'path-sqli-db',
    confidence: 0.95,
    riskBefore: 92,
    riskAfter: 15,
    primaryAffectedAssetId: 'nexus-target',
    relatedAssetIds: ['api-gateway', 'db-prod'],
    cveId: 'CVE-2023-48788',
    technique: 'T1190 · SQL Injection',
    summary: 'Automated SQL injection probes targeting public authentication routes with payload union select bypassing sanitization.',
    description: `Automated vulnerability scanner executed complex UNION SELECT payloads containing database metadata extraction functions against the /api/auth and /api/tickets endpoints from source IP 203.0.113.99.

Target database security guardrails intercepted anomalous query parsing syntax. Telemetry correlation rules identified the multi-vector probe, generated cryptographic containment records, and enforced immediate perimeter IP quarantine. No customer database records were accessed or leaked.`,
  },
  {
    id: 'inc-20261025-01',
    title: 'Multi-Stage Lateral Movement & DCSync Incursion',
    severity: 'critical',
    status: 'resolved',
    openedAt: '2026-10-25T14:20:00Z',
    createdAt: '2026-10-25T14:20:00Z',
    detectionIds: ['det-dcsync-1', 'det-dcsync-2'],
    pathId: 'path-ad-dcsync',
    confidence: 0.96,
    riskBefore: 95,
    riskAfter: 12,
    primaryAffectedAssetId: 'auth-svc',
    relatedAssetIds: ['api-gateway', 'iam-vault'],
    cveId: 'CVE-2023-20198',
    technique: 'T1003.006 · DCSync',
    summary: 'Detected unauthorized Directory Replication Service RPC requests attempting credential synchronization.',
    description: `An unauthorized operator session originating from an internal test runner attempted to issue DSGetNCChanges RPC requests to simulate domain controller replication and extract cryptographic credential password hashes.

The directory monitor detected the non-DC replication attempt in real time. The active defense engine revoked the session token within 350ms, rotated administrative service secrets, and isolated the authentication node until identity credentials could be cryptographically verified.`,
  },
  {
    id: 'inc-20261025-02',
    title: 'Credential Stuffing & Privilege Escalation',
    severity: 'high',
    status: 'contained',
    openedAt: '2026-10-25T08:00:00Z',
    createdAt: '2026-10-25T08:00:00Z',
    detectionIds: ['det-1', 'det-2'],
    pathId: 'path-1',
    confidence: 0.89,
    riskBefore: 84,
    riskAfter: 20,
    primaryAffectedAssetId: 'auth-svc',
    relatedAssetIds: ['api-gate', 'web-app'],
    cveId: 'CVE-2023-20198',
    technique: 'T1110 · Brute Force',
    summary: 'Observed high-velocity credential brute force against administrative endpoints.',
    description: `High-frequency credential stuffing campaign targeted operator administrative login forms across web portals. Over 450 distinct credential pairs were attempted within a 90-second window. Rate limiting heuristics engaged, temporarily locking compromised routes and blacklisting adversary gateway nodes.`,
  },
  {
    id: 'inc-20261024-01',
    title: 'Container Escape & Namespace Breakout',
    severity: 'critical',
    status: 'resolved',
    openedAt: '2026-10-24T11:05:00Z',
    createdAt: '2026-10-24T11:05:00Z',
    detectionIds: ['det-esc-1'],
    pathId: 'path-esc-host',
    confidence: 0.99,
    riskBefore: 99,
    riskAfter: 10,
    primaryAffectedAssetId: 'web-app',
    relatedAssetIds: ['container-host'],
    cveId: 'CVE-2024-21626',
    technique: 'T1611 · Escape to Host',
    summary: 'Anomalous /proc/self/fd file descriptor traversal attempting container breakout to host filesystem.',
    description: `Adversary exploited runc file descriptor leakage (CVE-2024-21626) to overwrite host binaries from inside a temporary sandboxed container.

Runtime eBPF kernel monitors detected anomalous file descriptor traversal pointing to /proc/self/fd/7 on the host filesystem. The container task was terminated immediately, memory dumps were collected for forensic reverse-engineering, and container daemon patches were enforced cluster-wide.`,
  },
  {
    id: 'inc-20261023-01',
    title: 'Ransomware Pre-Execution & Shadow Copy Deletion',
    severity: 'critical',
    status: 'resolved',
    openedAt: '2026-10-23T09:30:00Z',
    createdAt: '2026-10-23T09:30:00Z',
    detectionIds: ['det-vss-1', 'det-vss-2'],
    pathId: 'path-ransom-db',
    confidence: 0.97,
    riskBefore: 98,
    riskAfter: 14,
    primaryAffectedAssetId: 'db-prod',
    relatedAssetIds: ['backup-vault'],
    cveId: 'CVE-2022-30190',
    technique: 'T1490 · Inhibit System Recovery',
    summary: 'Execution of vssadmin delete shadows /all attempting to inhibit system recovery.',
    description: `Adversary staged executable scripts invoking vssadmin.exe and bcdedit.exe to disable automatic Windows recovery routines and purge volume shadow copies prior to planned database encryption.

Endpoint detection agents flagged the malicious batch invocations, terminated the parent process tree, isolated the host network adapter, and verified that all immutable backup snapshots remained uncompromised.`,
  },
];

export function IncidentArchiveView({
  incidents = [],
  onSelectIncident,
  className,
  initialFolderDate = null,
  initialSelectedIncidentId = null,
}: IncidentArchiveViewProps) {
  const [activeFolderDate, setActiveFolderDate] = useState<string | null>(initialFolderDate);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(initialSelectedIncidentId);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    if (initialFolderDate) {
      setActiveFolderDate(initialFolderDate);
    }
  }, [initialFolderDate]);

  useEffect(() => {
    if (initialSelectedIncidentId) {
      setSelectedIncidentId(initialSelectedIncidentId);
    }
  }, [initialSelectedIncidentId]);

  const archivedFromUI = useUI((s) => s.archivedIncidents);

  // Merge live incidents with fallback baseline incidents and UI dynamic archives
  const allIncidents = useMemo(() => {
    const map = new Map<string, Incident>();
    for (const inc of FALLBACK_ARCHIVED_INCIDENTS) {
      map.set(inc.id, inc);
    }
    for (const inc of (archivedFromUI || [])) {
      map.set(inc.id, {
        id: inc.id,
        title: inc.title,
        severity: (inc.severity as any) || 'critical',
        status: (inc.status as any) || 'contained',
        openedAt: inc.openedAt,
        createdAt: inc.createdAt || inc.openedAt,
        detectionIds: inc.detectionIds || [],
        confidence: 0.99,
        riskBefore: inc.riskBefore || 99,
        riskAfter: inc.riskAfter || 15,
        primaryAffectedAssetId: inc.primaryAffectedAssetId,
        cveId: inc.cveId || 'CVE-2023-34362',
        technique: inc.technique || 'T1190 · Exploit Public-Facing App',
        summary: inc.summary,
        description: inc.description,
      } as Incident);
    }
    for (const inc of incidents) {
      const existing = map.get(inc.id);
      map.set(inc.id, {
        ...existing,
        ...inc,
        description: inc.description || (inc as any).summary || existing?.description || 'Archived incident record.',
        summary: inc.summary || (inc as any).description || existing?.summary || 'Archived incident summary.',
      });
    }
    return Array.from(map.values());
  }, [incidents, archivedFromUI]);

  // Group incidents by calendar date (YYYY-MM-DD)
  const dateFolders = useMemo(() => {
    const groups = new Map<string, Incident[]>();

    for (const inc of allIncidents) {
      const rawDate = inc.openedAt || inc.createdAt || new Date().toISOString();
      const dateKey = rawDate.slice(0, 10); // "YYYY-MM-DD"
      if (!groups.has(dateKey)) {
        groups.set(dateKey, []);
      }
      groups.get(dateKey)!.push(inc);
    }

    // Sort dates in descending order (newest first)
    const sortedDates = Array.from(groups.keys()).sort((a, b) => b.localeCompare(a));

    return sortedDates.map((dateKey) => {
      const dateIncidents = groups.get(dateKey)!;
      const criticals = dateIncidents.filter(
        (i) => String(i.severity).toLowerCase() === 'critical'
      );
      const highs = dateIncidents.filter(
        (i) => String(i.severity).toLowerCase() === 'high'
      );

      // Pretty date formatting
      const dateObj = new Date(`${dateKey}T12:00:00Z`);
      const isToday = dateKey === new Date().toISOString().slice(0, 10);
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const isYesterday = dateKey === yesterday.toISOString().slice(0, 10);

      const label = isToday
        ? `${dateObj.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })} (Today)`
        : isYesterday
        ? `${dateObj.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })} (Yesterday)`
        : dateObj.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });

      return {
        dateKey,
        label,
        incidents: dateIncidents,
        criticalIncidents: criticals,
        highIncidents: highs,
        totalCount: dateIncidents.length,
      };
    });
  }, [allIncidents]);

  // Active folder data
  const currentFolder = useMemo(() => {
    if (!activeFolderDate) return null;
    return dateFolders.find((f) => f.dateKey === activeFolderDate) || null;
  }, [activeFolderDate, dateFolders]);

  // Incidents to display in active folder (filtered by search)
  const folderCriticalIncidents = useMemo(() => {
    if (!currentFolder) return [];
    // Prioritize critical and high incidents
    const list = currentFolder.incidents.filter((inc) => {
      const sev = String(inc.severity).toLowerCase();
      return sev === 'critical' || sev === 'high';
    });

    if (!searchTerm.trim()) return list;
    const term = searchTerm.toLowerCase();
    return list.filter((inc) => {
      return (
        inc.title.toLowerCase().includes(term) ||
        inc.id.toLowerCase().includes(term) ||
        (inc.description || '').toLowerCase().includes(term) ||
        (inc.summary || '').toLowerCase().includes(term) ||
        (inc.cveId || '').toLowerCase().includes(term) ||
        (inc.technique || '').toLowerCase().includes(term)
      );
    });
  }, [currentFolder, searchTerm]);

  // Selected incident details
  const selectedIncident = useMemo(() => {
    if (!selectedIncidentId) return null;
    return allIncidents.find((i) => i.id === selectedIncidentId) || null;
  }, [selectedIncidentId, allIncidents]);

  return (
    <div className={`space-y-4 ${className || ''}`}>
      {/* Top Banner / Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-card/90 p-3 rounded-lg border border-border">
        <div className="flex items-center gap-2">
          {activeFolderDate ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setActiveFolderDate(null);
                setSelectedIncidentId(null);
              }}
              className="h-7 text-[11px] gap-1 px-2 border-border"
            >
              <ArrowLeft className="size-3" /> Back to Date Folders
            </Button>
          ) : null}

          <div>
            <div className="text-[13px] font-bold text-foreground flex items-center gap-1.5">
              <span>{activeFolderDate ? `Archive Folder: ${currentFolder?.label}` : 'Incident Archives (Grouped by Date)'}</span>
              <Badge variant="outline" className="font-mono text-[9px] border-border text-muted-foreground">
                {activeFolderDate ? `${folderCriticalIncidents.length} Critical Cases` : `${dateFolders.length} Date Folders`}
              </Badge>
            </div>
            <div className="text-[10.5px] text-muted-foreground">
              {activeFolderDate
                ? 'Touch or click any critical incident card to inspect its full forensic description and mitigation history.'
                : 'Touch or click any folder below to inspect all archived critical security incidents recorded on that date.'}
            </div>
          </div>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-[220px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3 text-muted-foreground" />
          <Input
            placeholder="Search incident, CVE, text…"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="h-7 pl-7 text-[11px] bg-secondary/50 border-border"
          />
        </div>
      </div>

      {/* VIEW 1: DATE FOLDERS GRID (When no folder is opened) */}
      {!activeFolderDate && (
        <div>
          <div className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground mb-3 flex items-center gap-1.5">
            <Calendar className="size-3.5 text-primary" />
            <span>Select an Archive Folder by Date</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {dateFolders.map((folder) => {
              const hasCritical = folder.criticalIncidents.length > 0;

              return (
                <div
                  key={folder.dateKey}
                  onClick={() => {
                    setActiveFolderDate(folder.dateKey);
                    setSelectedIncidentId(null);
                  }}
                  className="group relative cursor-pointer transition-all duration-200 transform hover:-translate-y-1"
                >
                  

                  {/* Folder Body Container */}
                  <Card className="p-4 border-border hover:border-primary/40 bg-card hover:bg-secondary/20 transition-all rounded-lg">
                    <div className="flex items-start justify-between mb-3">
                      

                      {hasCritical && (
                        <Badge variant="outline" className="font-mono text-[9px] px-1.5 py-0.5 border-border text-foreground">
                          {folder.criticalIncidents.length} CRITICAL
                        </Badge>
                      )}
                    </div>

                    {/* Date Title */}
                    <div className="text-[13px] font-bold text-foreground group-hover:text-foreground transition-colors">
                      {folder.label}
                    </div>

                    <div className="text-[10px] font-mono text-muted-foreground mt-0.5 flex items-center gap-1">
                      <Calendar className="size-2.5" />
                      <span>{folder.dateKey} · env-prod</span>
                    </div>

                    {/* Folder Incident Metrics */}
                    <div className="mt-3 pt-2.5 border-t border-border/80 flex items-center justify-between text-[11px]">
                      <span className="text-muted-foreground font-mono text-[10px]">
                        {folder.totalCount} Total Incidents
                      </span>

                      <span className="text-[10.5px] font-semibold text-muted-foreground group-hover:text-foreground flex items-center gap-1">
                        Open Folder <ChevronRight className="size-3" />
                      </span>
                    </div>
                  </Card>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* VIEW 2: INSIDE A DATE FOLDER (Critical Incidents List) */}
      {activeFolderDate && (
        <div className="space-y-3">
          <div className="flex items-center justify-between text-[11.5px] text-muted-foreground">
            <div className="flex items-center gap-1.5 font-medium">
              
              <span>Showing Critical Incidents in <strong>{currentFolder?.label}</strong>:</span>
            </div>
            <span className="text-[11px] font-mono text-muted-foreground">
              Click an incident card to view its description
            </span>
          </div>

          {folderCriticalIncidents.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-8 text-center text-muted-foreground text-[12px]">
              No critical incidents matched the search filter for this date.
            </div>
          ) : (
            <div className="space-y-2.5">
              {folderCriticalIncidents.map((inc) => {
                const isSelected = selectedIncidentId === inc.id;
                const isCritical = String(inc.severity).toLowerCase() === 'critical';

                return (
                  <Card
                    key={inc.id}
                    onClick={() => {
                      setSelectedIncidentId(isSelected ? null : inc.id);
                      if (onSelectIncident) onSelectIncident(inc);
                    }}
                    className={`cursor-pointer p-4 transition-all border ${
                      isSelected
                        ? 'border-primary ring-2 ring-primary/30 bg-secondary/30'
                        : isCritical
                        ? 'border-red-500/40 hover:border-red-500/80 bg-card/90'
                        : 'border-border hover:border-primary/50 bg-card/90'
                    }`}
                  >
                    {/* Header Row */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge
                          variant="outline"
                          className="font-mono text-[9.5px] uppercase font-bold tracking-wider"
                        >
                          {inc.severity}
                        </Badge>

                        <span className="font-mono text-[11px] font-bold text-primary">
                          {inc.id}
                        </span>

                        <span className="text-[13px] font-bold text-foreground">
                          {inc.title}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={
                            String(inc.status).toLowerCase() === 'contained' || String(inc.status).toLowerCase() === 'resolved'
                              ? 'border-border text-foreground font-mono text-[9px]'
                              : 'border-border text-muted-foreground font-mono text-[9px]'
                          }
                        >
                          {String(inc.status).toUpperCase()}
                        </Badge>

                        <div className="text-muted-foreground">
                          {isSelected ? (
                            <ChevronDown className="size-4 text-primary" />
                          ) : (
                            <ChevronRight className="size-4" />
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Summary row */}
                    <p className="text-[11.5px] text-muted-foreground mb-2 leading-relaxed">
                      {inc.summary || inc.description}
                    </p>

                    {/* Metadata tags */}
                    <div className="flex flex-wrap items-center gap-3 text-[10.5px] font-mono text-muted-foreground">
                      {inc.cveId && (
                        <span className="text-red-400 font-semibold bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
                          {inc.cveId}
                        </span>
                      )}
                      {inc.technique && (
                        <span className="text-muted-foreground bg-secondary px-1.5 py-0.5 rounded">
                          {inc.technique}
                        </span>
                      )}
                      {inc.primaryAffectedAssetId && (
                        <span className="flex items-center gap-1 text-foreground">
                          
                          {inc.primaryAffectedAssetId}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        
                        {new Date(inc.openedAt || inc.createdAt || '').toLocaleTimeString()}
                      </span>
                    </div>

                    {/* EXPANDABLE FULL FORENSIC DESCRIPTION (Shown when touched / clicked) */}
                    {isSelected && (
                      <div className="mt-3.5 pt-3.5 border-t border-border space-y-3">
                        <div className="rounded-lg border border-primary/40 bg-primary/5 p-3.5 space-y-2">
                          <div className="text-[11.5px] font-bold text-foreground flex items-center gap-1.5">
                            <Info className="size-3.5 text-primary" />
                            <span>Comprehensive Forensic Incursion Narrative:</span>
                          </div>

                          <div className="text-[12px] leading-relaxed text-foreground/90 whitespace-pre-line">
                            {inc.description || inc.summary}
                          </div>
                        </div>

                        {/* Forensic Intelligence Grid */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10.5px] font-mono bg-secondary/40 p-2.5 rounded-lg border border-border">
                          <div>
                            <span className="text-muted-foreground">Risk Before:</span>{' '}
                            <strong className="text-red-400">{inc.riskBefore ?? 95}</strong>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Risk Contained:</span>{' '}
                            <strong className="text-primary">{inc.riskAfter ?? 15}</strong>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Confidence:</span>{' '}
                            <strong className="text-foreground">{((inc.confidence || 0.95) * 100).toFixed(0)}%</strong>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Detections:</span>{' '}
                            <strong className="text-primary">{inc.detectionIds?.length ?? 1} events</strong>
                          </div>
                        </div>

                        {/* Action Shortcuts */}
                        <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
                          <Link href={`/incidents/${inc.id}`}>
                            <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1 px-2.5">
                              Reconstruct Story &rarr;
                            </Button>
                          </Link>

                          <Link href={`/telemetry?inspect=${inc.detectionIds?.[0] || inc.id}`}>
                            <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1 px-2.5">
                              Observe Telemetry &rarr;
                            </Button>
                          </Link>

                          <Link href="/database">
                            <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1 px-2.5 border-border text-foreground">
                              Database Containment &rarr;
                            </Button>
                          </Link>
                        </div>
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

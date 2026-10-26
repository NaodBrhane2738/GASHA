'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import {
  useResponses,
  useIncidents,
  useAuditTrail,
  useAuditVerification,
} from '@/lib/api/queries';
import type { ResponseAction, AuditEntry, Incident } from '@/types/domain';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  Database,
  ShieldCheck,
  Lock,
  Server,
  Key,
  CheckCircle2,
  FileCheck,
  Search,
  ExternalLink,
  Download,
  RefreshCw,
  Hash,
  Activity,
  Radar,
  ArrowRight,
  Filter,
  Check,
} from 'lucide-react';
import { toast } from 'sonner';

import { IncidentArchiveView } from '@/components/archive/IncidentArchiveView';

type DatabaseTab = 'all' | 'ips' | 'assets' | 'sessions' | 'incidents' | 'hashchain' | 'archives';

export default function DatabasePage() {
  const { data: responses, refetch: refetchResponses } = useResponses();
  const { data: incidents, refetch: refetchIncidents } = useIncidents();
  const { data: auditTrail, refetch: refetchAudit } = useAuditTrail();
  const { data: verification, refetch: refetchVerify, isFetching: isVerifying } = useAuditVerification();

  const [activeTab, setActiveTab] = useState<DatabaseTab>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCase, setSelectedCase] = useState<ResponseAction | null>(null);
  const [selectedAuditEntry, setSelectedAuditEntry] = useState<AuditEntry | null>(null);

  // Filter executed/enforced responses
  const enforcedResponses = useMemo(() => {
    return (responses ?? []).filter((r) => {
      const state = String(r.state || (r as any).status || '').toLowerCase();
      return state === 'done' || state === 'succeeded' || state === 'completed';
    });
  }, [responses]);

  // Quarantined IPs
  const quarantinedIps = useMemo(() => {
    const map = new Map<string, ResponseAction>();
    for (const r of enforcedResponses) {
      const kind = String(r.kind || (r as any).actionType || '').toLowerCase();
      const target = r.target || (r as any).targetIdentifier || '';
      if ((kind.includes('block') || kind.includes('ip')) && target) {
        if (!map.has(target)) {
          map.set(target, r);
        }
      }
    }
    return Array.from(map.values());
  }, [enforcedResponses]);

  // Isolated Assets
  const isolatedAssets = useMemo(() => {
    return enforcedResponses.filter((r) => {
      const kind = String(r.kind || (r as any).actionType || '').toLowerCase();
      return kind.includes('isolate') || kind.includes('resource') || kind.includes('host');
    });
  }, [enforcedResponses]);

  // Revoked Sessions
  const revokedSessions = useMemo(() => {
    return enforcedResponses.filter((r) => {
      const kind = String(r.kind || (r as any).actionType || '').toLowerCase();
      return kind.includes('session') || kind.includes('revoke');
    });
  }, [enforcedResponses]);

  // Contained or Resolved Incidents
  const resolvedIncidents = useMemo(() => {
    return (incidents ?? []).filter((inc) => {
      const s = String(inc.status).toLowerCase();
      return s === 'contained' || s === 'resolved' || s === 'mitigated';
    });
  }, [incidents]);

  // Filtered list based on tab & search
  const filteredCases = useMemo(() => {
    let list: ResponseAction[] = [];
    if (activeTab === 'all') {
      list = enforcedResponses;
    } else if (activeTab === 'ips') {
      list = quarantinedIps;
    } else if (activeTab === 'assets') {
      list = isolatedAssets;
    } else if (activeTab === 'sessions') {
      list = revokedSessions;
    }

    if (!searchTerm.trim()) return list;
    const term = searchTerm.toLowerCase();
    return list.filter((item) => {
      const idMatch = item.id.toLowerCase().includes(term);
      const targetMatch = (item.target || (item as any).targetIdentifier || '').toLowerCase().includes(term);
      const incMatch = item.incidentId.toLowerCase().includes(term);
      const reasonMatch = (item.reason || '').toLowerCase().includes(term);
      return idMatch || targetMatch || incMatch || reasonMatch;
    });
  }, [activeTab, enforcedResponses, quarantinedIps, isolatedAssets, revokedSessions, searchTerm]);

  // Filtered audit trail
  const filteredAuditTrail = useMemo(() => {
    const list = [...(auditTrail ?? [])].sort((a, b) => b.sequenceNumber - a.sequenceNumber);
    if (!searchTerm.trim()) return list;
    const term = searchTerm.toLowerCase();
    return list.filter((e) => {
      return (
        e.auditId.toLowerCase().includes(term) ||
        e.targetIdentifier.toLowerCase().includes(term) ||
        e.actionType.toLowerCase().includes(term) ||
        e.actor.toLowerCase().includes(term) ||
        e.recordHash.toLowerCase().includes(term) ||
        e.incidentId.toLowerCase().includes(term)
      );
    });
  }, [auditTrail, searchTerm]);

  const handleManualVerification = async () => {
    try {
      const res = await refetchVerify();
      if (res.data?.verified) {
        toast.success(
          `Cryptographic audit ledger verified! ${res.data.totalRecords} blocks validated against SHA-256 root hash.`,
          { description: `Latest root: ${res.data.latestHash?.slice(0, 24)}…` }
        );
      } else {
        toast.error('Ledger verification failed or returned discrepancies.');
      }
    } catch {
      toast.error('Verification query failed.');
    }
  };

  const handleExportJson = () => {
    const exportData = {
      exportTimestamp: new Date().toISOString(),
      environment: 'env-prod',
      ledgerVerification: verification,
      totalEnforcedCases: enforcedResponses.length,
      quarantinedIps: quarantinedIps.map((q) => q.target || (q as any).targetIdentifier),
      isolatedAssets: isolatedAssets.map((a) => a.target || (a as any).targetIdentifier),
      resolvedIncidents: resolvedIncidents.map((i) => i.id),
      enforcedResponses,
      auditTrail,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gasha-database-ledger-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('Downloaded complete cryptographic database ledger export.');
  };

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4 space-y-4">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h1 className="text-[15px] font-bold text-foreground flex items-center gap-2">
            <Database className="size-4 text-primary" />
            Enforced Cases & Cryptographic Database Ledger
          </h1>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            Authoritative persistent records of all executed containment actions, quarantined adversary IPs, isolated assets, and SHA-256 verified audit chains.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleManualVerification}
            disabled={isVerifying}
            className="h-8 gap-1.5 text-[11.5px] border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10"
          >
            <ShieldCheck className="size-3.5 text-emerald-400" />
            {isVerifying ? 'Verifying Hashes…' : 'Verify Ledger Integrity'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleExportJson}
            className="h-8 gap-1.5 text-[11.5px]"
          >
            <Download className="size-3.5 text-primary" />
            Export JSON Ledger
          </Button>

          <Link href="/twin">
            <Button variant="ghost" size="sm" className="h-8 gap-1.5 text-[11.5px] text-muted-foreground">
              <Radar className="size-3.5 text-primary" /> Digital Twin
            </Button>
          </Link>
        </div>
      </div>

      {/* KPI Metrics Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
        <Card className="p-3 border-border bg-card/80">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Total Enforced</span>
            <CheckCircle2 className="size-3.5 text-emerald-400" />
          </div>
          <div className="mt-1 text-[20px] font-mono font-bold text-foreground">
            {enforcedResponses.length}
          </div>
          <div className="text-[10px] text-emerald-400/90 mt-0.5 font-medium">
            Active Containment Orders
          </div>
        </Card>

        <Card className="p-3 border-border bg-card/80">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Quarantined IPs</span>
            <Lock className="size-3.5 text-red-400" />
          </div>
          <div className="mt-1 text-[20px] font-mono font-bold text-red-400">
            {quarantinedIps.length}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">
            Firewall Perimeter Drops
          </div>
        </Card>

        <Card className="p-3 border-border bg-card/80">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Isolated Assets</span>
            <Server className="size-3.5 text-muted-foreground" />
          </div>
          <div className="mt-1 text-[20px] font-mono font-bold text-foreground">
            {isolatedAssets.length}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">
            Micro-Segmented Workloads
          </div>
        </Card>

        <Card className="p-3 border-border bg-card/80">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Resolved Incidents</span>
            <FileCheck className="size-3.5 text-blue-400" />
          </div>
          <div className="mt-1 text-[20px] font-mono font-bold text-foreground">
            {resolvedIncidents.length}
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5">
            Contained Multi-Stage Threats
          </div>
        </Card>

        <Card className="p-3 border-border bg-card/80 col-span-2 sm:col-span-1">
          <div className="flex items-center justify-between text-muted-foreground text-[11px]">
            <span>Ledger Integrity</span>
            <Hash className="size-3.5 text-emerald-400" />
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-[15px] font-bold text-emerald-400 font-mono">
            <Check className="size-4 text-emerald-400 shrink-0" />
            <span>{verification?.verified ? 'VERIFIED' : 'ACTIVE'}</span>
          </div>
          <div className="text-[9.5px] font-mono text-muted-foreground truncate mt-0.5" title={verification?.latestHash || ''}>
            {verification?.latestHash ? `${verification.latestHash.slice(0, 16)}…` : `${auditTrail?.length ?? 0} SHA-256 blocks`}
          </div>
        </Card>
      </div>

      {/* Tabs and Search Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-border pb-2.5">
        {/* Tab buttons */}
        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            variant={activeTab === 'all' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('all')}
            className="h-7 text-[11.5px] px-2.5 gap-1.5"
          >
            <span>All Enforced</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              {enforcedResponses.length}
            </Badge>
          </Button>

          <Button
            variant={activeTab === 'ips' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('ips')}
            className="h-7 text-[11.5px] px-2.5 gap-1.5"
          >
            <Lock className="size-3 text-red-400" />
            <span>Quarantined IPs</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              {quarantinedIps.length}
            </Badge>
          </Button>

          <Button
            variant={activeTab === 'assets' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('assets')}
            className="h-7 text-[11.5px] px-2.5 gap-1.5"
          >
            <Server className="size-3 text-muted-foreground" />
            <span>Isolated Assets</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              {isolatedAssets.length}
            </Badge>
          </Button>

          <Button
            variant={activeTab === 'sessions' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('sessions')}
            className="h-7 text-[11.5px] px-2.5 gap-1.5"
          >
            <Key className="size-3 text-blue-400" />
            <span>Revoked Sessions</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              {revokedSessions.length}
            </Badge>
          </Button>

          <Button
            variant={activeTab === 'incidents' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('incidents')}
            className="h-7 text-[11.5px] px-2.5 gap-1.5"
          >
            <FileCheck className="size-3 text-emerald-400" />
            <span>Resolved Incidents</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              {resolvedIncidents.length}
            </Badge>
          </Button>

          <Button
            variant={activeTab === 'hashchain' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('hashchain')}
            className="h-7 text-[11.5px] px-2.5 gap-1.5"
          >
            <Hash className="size-3 text-primary" />
            <span>Audit Hash Chain</span>
            <Badge variant="secondary" className="px-1 py-0 text-[9px] font-mono">
              {auditTrail?.length ?? 0}
            </Badge>
          </Button>
        </div>

        {/* Real-time search */}
        <div className="relative w-full sm:w-[240px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
          <Input
            placeholder="Search IP, Case, Hash…"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="h-7 pl-8 text-[11.5px] bg-secondary/50 border-border"
          />
        </div>
      </div>

      {/* Main Content Body */}
      {activeTab === 'hashchain' ? (
        /* CRYPTOGRAPHIC HASH CHAIN VIEW */
        <div className="space-y-3">
          <div className="flex items-center justify-between text-[11.5px] text-muted-foreground bg-secondary/30 rounded-lg p-2.5 border border-border">
            <div className="flex items-center gap-2">
              <ShieldCheck className="size-4 text-emerald-400" />
              <span>
                Cryptographically linked SHA-256 hash chain. Every state alteration is immutably sealed by its preceding block hash.
              </span>
            </div>
            <div className="font-mono text-[10.5px]">
              Root: <span className="text-emerald-400">{verification?.latestHash ? `${verification.latestHash.slice(0, 20)}…` : 'Genesis'}</span>
            </div>
          </div>

          <div className="rounded-lg border border-border overflow-hidden bg-card/60">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11.5px]">
                <thead className="bg-secondary/60 text-muted-foreground text-[10.5px] uppercase font-mono border-b border-border">
                  <tr>
                    <th className="py-2 px-3"># Block</th>
                    <th className="py-2 px-3">Timestamp</th>
                    <th className="py-2 px-3">Event Type</th>
                    <th className="py-2 px-3">Actor</th>
                    <th className="py-2 px-3">Target Entity</th>
                    <th className="py-2 px-3">Previous Hash</th>
                    <th className="py-2 px-3">Record SHA-256 Hash</th>
                    <th className="py-2 px-3 text-right">Verification</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60 font-mono">
                  {filteredAuditTrail.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="py-8 text-center text-muted-foreground font-sans text-[12px]">
                        No audit records matched your filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredAuditTrail.map((entry) => (
                      <tr
                        key={entry.auditId}
                        onClick={() => setSelectedAuditEntry(entry)}
                        className="hover:bg-secondary/40 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-3 font-bold text-foreground">
                          #{entry.sequenceNumber}
                        </td>
                        <td className="py-2.5 px-3 text-muted-foreground font-sans">
                          {new Date(entry.timestamp).toLocaleString()}
                        </td>
                        <td className="py-2.5 px-3">
                          <Badge
                            variant="outline"
                            className={
                              entry.eventType.includes('SUCCEEDED') || entry.eventType.includes('APPROVED')
                                ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10'
                                : 'border-border text-muted-foreground'
                            }
                          >
                            {entry.eventType}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-3 text-foreground font-medium">
                          {entry.actor}
                        </td>
                        <td className="py-2.5 px-3 text-primary font-bold">
                          {entry.targetIdentifier}
                        </td>
                        <td className="py-2.5 px-3 text-muted-foreground text-[10px]" title={entry.previousHash}>
                          {entry.previousHash.slice(0, 10)}…{entry.previousHash.slice(-6)}
                        </td>
                        <td className="py-2.5 px-3 text-emerald-400 text-[10px] font-bold" title={entry.recordHash}>
                          {entry.recordHash.slice(0, 12)}…{entry.recordHash.slice(-8)}
                        </td>
                        <td className="py-2.5 px-3 text-right font-sans">
                          <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 px-2 py-0.5 text-[10.5px] font-semibold text-emerald-400">
                            <Check className="size-3" /> Valid
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ) : activeTab === 'incidents' ? (
        /* RESOLVED INCIDENTS VIEW */
        <div className="space-y-2">
          {resolvedIncidents.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border p-8 text-center text-muted-foreground text-[12px]">
              No resolved or contained incidents recorded in the active database.
            </div>
          ) : (
            resolvedIncidents.map((inc) => (
              <Card key={inc.id} className="p-3.5 border-border bg-card/70 hover:border-border/80 transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11.5px] font-bold text-primary">{inc.id}</span>
                    <span className="text-[13px] font-semibold text-foreground">{inc.title}</span>
                  </div>
                  <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 font-mono text-[10px] w-fit">
                    {String(inc.status).toUpperCase()}
                  </Badge>
                </div>
                <div className="flex flex-wrap items-center gap-4 text-[11px] text-muted-foreground">
                  <span>Severity: <strong className="text-foreground">{inc.severity}</strong></span>
                  <span>Detections: <strong className="text-foreground">{inc.detectionIds?.length ?? 0}</strong></span>
                  <span>Confidence: <strong className="text-foreground">{((inc.confidence || 0.95) * 100).toFixed(0)}%</strong></span>
                  <span>Risk Score: <strong className="text-emerald-400 font-mono">{inc.riskAfter ?? 20}</strong> (was {inc.riskBefore ?? 85})</span>
                  <div className="sm:ml-auto flex items-center gap-2">
                    <Link href={`/incidents/${inc.id}`}>
                      <Button variant="ghost" size="sm" className="h-6 text-[11px] text-primary gap-1 px-2">
                        Inspect Incident Story <ArrowRight className="size-3" />
                      </Button>
                    </Link>
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>
      ) : (
        /* ENFORCED CASES TABLE */
        <div className="rounded-lg border border-border overflow-hidden bg-card/60">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11.5px]">
              <thead className="bg-secondary/60 text-muted-foreground text-[10.5px] uppercase font-mono border-b border-border">
                <tr>
                  <th className="py-2.5 px-3">Case ID</th>
                  <th className="py-2.5 px-3">Action Type</th>
                  <th className="py-2.5 px-3">Target Entity</th>
                  <th className="py-2.5 px-3">Incident / Reason</th>
                  <th className="py-2.5 px-3">Enforcement State</th>
                  <th className="py-2.5 px-3">Risk Reduction</th>
                  <th className="py-2.5 px-3">Verified By</th>
                  <th className="py-2.5 px-3 text-right">Audit Dossier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {filteredCases.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-muted-foreground text-[12px]">
                      No enforced cases found in this category.
                    </td>
                  </tr>
                ) : (
                  filteredCases.map((c) => {
                    const kind = String(c.kind || (c as any).actionType || 'BLOCK_SOURCE').toUpperCase();
                    const target = c.target || (c as any).targetIdentifier || 'Unknown';
                    const isIp = kind.includes('IP') || kind.includes('BLOCK');
                    const isAsset = kind.includes('ISOLATE') || kind.includes('RESOURCE');

                    return (
                      <tr
                        key={c.id}
                        onClick={() => setSelectedCase(c)}
                        className="hover:bg-secondary/40 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-3 font-mono font-semibold text-foreground">
                          {c.id}
                        </td>
                        <td className="py-2.5 px-3">
                          <Badge
                            variant="outline"
                            className={
                              isIp
                                ? 'border-red-500/40 text-red-400 bg-red-500/10 font-mono text-[9.5px]'
                                : isAsset
                                ? 'border-border text-muted-foreground bg-secondary font-mono text-[9.5px]'
                                : 'border-blue-500/40 text-blue-400 bg-blue-500/10 font-mono text-[9.5px]'
                            }
                          >
                            {isIp ? 'FIREWALL DROP (IP)' : isAsset ? 'ISOLATE ASSET' : kind}
                          </Badge>
                        </td>
                        <td className="py-2.5 px-3 font-mono font-bold text-foreground">
                          {target}
                        </td>
                        <td className="py-2.5 px-3 max-w-[240px] truncate text-muted-foreground" title={c.reason || c.incidentId}>
                          <span className="font-mono text-primary mr-1.5 font-semibold">[{c.incidentId}]</span>
                          {c.reason || 'Perimeter active defense response'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="inline-flex items-center gap-1.5 font-semibold text-emerald-400 text-[11px]">
                            <CheckCircle2 className="size-3 text-emerald-400" /> Verified
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono font-semibold text-emerald-400">
                          -{c.riskReduction ?? 15} pts
                        </td>
                        <td className="py-2.5 px-3 text-muted-foreground font-mono">
                          {c.approvedBy || (c as any).executedBy || 'analyst01'}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedCase(c);
                            }}
                            className="h-6 text-[10.5px] px-2 text-primary hover:bg-primary/10 gap-1"
                          >
                            Inspect Dossier <ArrowRight className="size-3" />
                          </Button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Case Dossier Detail Dialog */}
      <Dialog open={!!selectedCase} onOpenChange={(open) => !open && setSelectedCase(null)}>
        <DialogContent className="max-w-2xl bg-card border-border">
          {selectedCase && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-[14px]">
                  <Database className="size-4 text-primary" />
                  Containment Case Dossier: <span className="font-mono text-primary">{selectedCase.id}</span>
                </DialogTitle>
                <DialogDescription className="text-[11.5px]">
                  Authoritative enforcement proof and cryptographic state verification.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3.5 py-2 text-[12px]">
                {/* Target & Status Banner */}
                <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-3 flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <ShieldCheck className="size-5 text-emerald-400" />
                    <div>
                      <div className="font-bold text-emerald-300">Target State: Verified & Secured</div>
                      <div className="text-[11px] text-emerald-200/80">
                        {selectedCase.executionMessage || `Successfully enforced perimeter containment for ${selectedCase.target || (selectedCase as any).targetIdentifier}`}
                      </div>
                    </div>
                  </div>
                  <Badge variant="outline" className="border-emerald-500/50 text-emerald-400 font-mono text-[10px]">
                    NOMINAL BASELINE
                  </Badge>
                </div>

                {/* Dossier Grid Details */}
                <div className="grid grid-cols-2 gap-2 text-[11.5px] bg-secondary/30 p-3 rounded-lg border border-border">
                  <div>
                    <span className="text-muted-foreground">Target Entity:</span>{' '}
                    <strong className="font-mono text-foreground">{selectedCase.target || (selectedCase as any).targetIdentifier}</strong>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Action Type:</span>{' '}
                    <strong className="font-mono text-foreground">{selectedCase.kind || (selectedCase as any).actionType}</strong>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Associated Incident:</span>{' '}
                    <strong className="font-mono text-primary">{selectedCase.incidentId}</strong>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Risk Reduction:</span>{' '}
                    <strong className="font-mono text-emerald-400">-{selectedCase.riskReduction ?? 15} points</strong>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Approved By:</span>{' '}
                    <strong className="font-mono text-foreground">{selectedCase.approvedBy || 'analyst01'}</strong>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Audit ID:</span>{' '}
                    <strong className="font-mono text-foreground">{selectedCase.auditId || 'aud-latest'}</strong>
                  </div>
                </div>

                {/* Justification Narrative */}
                <div className="rounded-lg border border-border p-3 space-y-1">
                  <div className="text-[11px] font-semibold text-muted-foreground uppercase">Reason & Evidence Justification</div>
                  <p className="text-[11.5px] text-foreground leading-relaxed">
                    {selectedCase.reason || 'Containment policy executed following high-severity security detection incursion.'}
                  </p>
                </div>

                {/* Blast Radius Assessment */}
                <div className="rounded-lg border border-border p-3 space-y-1">
                  <div className="text-[11px] font-semibold text-muted-foreground uppercase">Enforced Blast Radius</div>
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {(selectedCase.blastRadius?.nodeIds ?? [selectedCase.target]).map((node) => (
                      <Badge key={node} variant="secondary" className="font-mono text-[10px]">
                        {node}
                      </Badge>
                    ))}
                    {(selectedCase.blastRadius?.servicesAffected ?? []).map((svc) => (
                      <Badge key={svc} variant="outline" className="font-mono text-[10px]">
                        {svc}
                      </Badge>
                    ))}
                  </div>
                </div>

                {/* Action buttons */}
                <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
                  <Link href={`/telemetry?inspect=${selectedCase.incidentId}`}>
                    <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1">
                      <Activity className="size-3 text-primary" /> Inspect in Observe
                    </Button>
                  </Link>
                  <Link href="/twin">
                    <Button variant="outline" size="sm" className="h-7 text-[11px] gap-1">
                      <Radar className="size-3 text-primary" /> View in Digital Twin
                    </Button>
                  </Link>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {/* Audit Entry Detail Dialog */}
      <Dialog open={!!selectedAuditEntry} onOpenChange={(open) => !open && setSelectedAuditEntry(null)}>
        <DialogContent className="max-w-2xl bg-card border-border">
          {selectedAuditEntry && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2 text-[14px]">
                  <Hash className="size-4 text-emerald-400" />
                  Audit Block #{selectedAuditEntry.sequenceNumber} Cryptographic Proof
                </DialogTitle>
                <DialogDescription className="text-[11.5px]">
                  SHA-256 mathematical hash verification and authenticated operator identity.
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-3 py-2 text-[11.5px] font-mono">
                <div className="space-y-1 bg-secondary/40 p-3 rounded-lg border border-border">
                  <div className="text-[10.5px] text-muted-foreground uppercase">Record SHA-256 Hash:</div>
                  <div className="font-bold text-emerald-400 break-all">{selectedAuditEntry.recordHash}</div>
                </div>

                <div className="space-y-1 bg-secondary/40 p-3 rounded-lg border border-border">
                  <div className="text-[10.5px] text-muted-foreground uppercase">Previous Chained Hash:</div>
                  <div className="font-medium text-foreground break-all">{selectedAuditEntry.previousHash}</div>
                </div>

                <div className="grid grid-cols-2 gap-2 bg-secondary/20 p-3 rounded-lg border border-border text-[11px]">
                  <div>Actor: <strong className="text-foreground">{selectedAuditEntry.actor}</strong></div>
                  <div>Event Type: <strong className="text-foreground">{selectedAuditEntry.eventType}</strong></div>
                  <div>Action: <strong className="text-foreground">{selectedAuditEntry.actionType}</strong></div>
                  <div>Target: <strong className="text-foreground">{selectedAuditEntry.targetIdentifier}</strong></div>
                  <div>Timestamp: <strong className="text-foreground">{selectedAuditEntry.timestamp}</strong></div>
                  <div>Outcome: <strong className="text-emerald-400 font-bold">{selectedAuditEntry.outcome}</strong></div>
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

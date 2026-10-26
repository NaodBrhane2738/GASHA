'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useProposeResponse } from '@/lib/api/queries';
import { toast } from 'sonner';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  Flame,
  Bug,
  Copy,
  Check,
  ExternalLink,
  Server,
  Crosshair,
  Lock,
  Terminal,
  Activity,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  Route,
} from 'lucide-react';
import { useUI } from '@/store/ui';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { DetailedIncidentDossier } from '@/lib/intelligence/cveMapping';

interface Props {
  dossier: DetailedIncidentDossier | null;
  onClose: () => void;
}

export function IncidentDossierModal({ dossier, onClose }: Props) {
  const router = useRouter();
  const proposeResponse = useProposeResponse();
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'narrative' | 'cve' | 'telemetry'>('narrative');

  if (!dossier) return null;

  const handleQuarantine = async () => {
    try {
      await proposeResponse.mutateAsync({
        incidentId: dossier.incidentId,
        actionType: 'BLOCK_SOURCE',
        targetType: 'IP_ADDRESS',
        targetIdentifier: dossier.attacker.ip,
        reason: `Quarantine adversary IP targeting asset ${dossier.targetAsset.label} via Observe dossier`,
        supportingEvidenceIds: [dossier.id],
      });
      toast.success(`Quarantine action queued for IP ${dossier.attacker.ip}`);
    } catch (e) {
      console.warn('Backend proposal note:', e);
    }
    onClose();
    router.push(`/response?quarantine=${dossier.attacker.ip}`);
  };

  const copyPayload = () => {
    navigator.clipboard.writeText(JSON.stringify(dossier.telemetryEvidence.rawPayload, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const isCritical = dossier.severity === 'critical';
  const isHigh = dossier.severity === 'high';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 p-4 backdrop-blur-sm sm:p-6 animate-in fade-in duration-200">
      <div
        className="relative flex h-[90vh] w-full max-w-4xl flex-col rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header */}
        <div className="flex items-center justify-between border-b border-border bg-secondary/40 px-6 py-4">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                'flex size-10 shrink-0 items-center justify-center rounded-lg border',
                isCritical
                  ? 'border-red-500/50 bg-red-500/15 text-red-500 shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                  : isHigh
                  ? 'border-orange-500/50 bg-orange-500/15 text-orange-400'
                  : 'border-yellow-500/50 bg-yellow-500/15 text-yellow-400',
              )}
            >
              <Flame className="size-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-[15px] font-bold text-foreground">{dossier.title}</h2>
                <Badge
                  variant={isCritical ? 'destructive' : 'outline'}
                  className="font-mono text-[10px] uppercase font-bold tracking-wider"
                >
                  {dossier.severity} SEVERITY
                </Badge>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-muted-foreground mt-0.5">
                <span className="font-mono text-primary font-semibold">{dossier.incidentId}</span>
                <span>&middot;</span>
                <span>Detected: {new Date(dossier.timestamp).toLocaleString()}</span>
              </div>
            </div>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="size-8 p-0 text-muted-foreground hover:text-foreground"
          >
            <X className="size-4" />
          </Button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center border-b border-border bg-secondary/20 px-6 text-[12px] font-medium">
          <button
            onClick={() => setActiveTab('narrative')}
            className={cn(
              'border-b-2 py-3 px-3 transition-colors flex items-center gap-1.5',
              activeTab === 'narrative'
                ? 'border-primary text-primary font-semibold'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            <ShieldAlert className="size-3.5" /> Incident Narrative & Attack Context
          </button>
          <button
            onClick={() => setActiveTab('cve')}
            className={cn(
              'border-b-2 py-3 px-3 transition-colors flex items-center gap-1.5',
              activeTab === 'cve'
                ? 'border-primary text-primary font-semibold'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            <Bug className="size-3.5" /> CVE Vulnerability & CVSS Dossier
          </button>
          <button
            onClick={() => setActiveTab('telemetry')}
            className={cn(
              'border-b-2 py-3 px-3 transition-colors flex items-center gap-1.5',
              activeTab === 'telemetry'
                ? 'border-primary text-primary font-semibold'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            <Terminal className="size-3.5" /> Forensic Telemetry Evidence
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'narrative' && (
            <div className="space-y-6">
              {/* Full Description Narrative Card */}
              <Card className="border-border bg-card p-5">
                <div className="flex items-center gap-2 text-[13px] font-semibold text-foreground mb-3">
                  <ShieldAlert className="size-4 text-primary" />
                  <h3>Full Incident Description</h3>
                </div>
                <p className="text-[13px] leading-relaxed text-muted-foreground">
                  {dossier.fullNarrative}
                </p>
                <div className="mt-4 rounded-lg border border-border/80 bg-secondary/30 p-3 text-[11.5px] font-mono text-muted-foreground">
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-foreground font-semibold">Evidence Indicator:</span>
                    <span className="text-primary font-bold">Confidence {(dossier.telemetryEvidence.confidence * 100).toFixed(0)}%</span>
                  </div>
                  <div>{dossier.summary}</div>
                </div>
              </Card>

              {/* Key Indicators Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="p-4 border-border bg-card">
                  <div className="text-[11px] font-medium text-muted-foreground mb-1">Attacker Vector</div>
                  <div className="font-mono text-[13px] font-bold text-red-400">{dossier.attacker.ip}</div>
                  <div className="text-[11px] text-muted-foreground mt-1 truncate">
                    Path: {dossier.attacker.targetPath}
                  </div>
                </Card>

                <Card className="p-4 border-border bg-card">
                  <div className="text-[11px] font-medium text-muted-foreground mb-1">Target Asset</div>
                  <div className="text-[13px] font-bold text-foreground">{dossier.targetAsset.label}</div>
                  <div className="text-[11px] text-muted-foreground mt-1 font-mono uppercase">
                    {dossier.targetAsset.kind} &middot; {dossier.targetAsset.exposure}
                  </div>
                </Card>

                <Card className="p-4 border-border bg-card">
                  <div className="text-[11px] font-medium text-muted-foreground mb-1">MITRE ATT&CK</div>
                  <div className="font-mono text-[13px] font-bold text-primary">{dossier.mitre.techniqueId}</div>
                  <div className="text-[11px] text-muted-foreground mt-1 truncate">
                    {dossier.mitre.techniqueName}
                  </div>
                </Card>
              </div>

              {/* MITRE ATT&CK Matrix Card */}
              <Card className="p-5 border-border bg-card">
                <div className="flex items-center gap-2 text-[13px] font-semibold text-foreground mb-2">
                  <Crosshair className="size-4 text-primary" />
                  <h3>MITRE ATT&CK Matrix Alignment</h3>
                </div>
                <div className="flex items-center gap-2 mb-3">
                  <Badge variant="outline" className="font-mono text-[11px] border-primary/40 text-primary">
                    Tactic: {dossier.mitre.tactic}
                  </Badge>
                  <Badge variant="outline" className="font-mono text-[11px]">
                    Technique: {dossier.mitre.techniqueId}
                  </Badge>
                </div>
                <p className="text-[12px] text-muted-foreground leading-relaxed">
                  {dossier.mitre.description}
                </p>
              </Card>
            </div>
          )}

          {activeTab === 'cve' && (
            <div className="space-y-6">
              {/* Primary CVE Banner */}
              <Card className="border-red-500/40 bg-gradient-to-r from-red-950/20 via-card to-card p-5">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="font-mono text-[16px] font-extrabold text-red-400">
                        {dossier.cve.id}
                      </span>
                      <Badge variant="destructive" className="font-mono text-[10px] font-bold">
                        CVSS {dossier.cve.cvssScore} {dossier.cve.cvssSeverity}
                      </Badge>
                    </div>
                    <div className="text-[13px] font-semibold text-foreground">
                      {dossier.cve.title}
                    </div>
                    <div className="text-[11.5px] font-mono text-muted-foreground mt-1">
                      {dossier.cve.cwe}
                    </div>
                  </div>

                  <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-right">
                    <div className="text-[10px] text-red-300 font-medium">Exploit Status</div>
                    <div className="text-[11px] font-bold text-red-400">{dossier.cve.exploitStatus}</div>
                  </div>
                </div>

                {/* Related CVE Aliases */}
                {dossier.cve.aliases.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-border flex items-center gap-2 text-[11px]">
                    <span className="text-muted-foreground">Related CVEs in attack family:</span>
                    {dossier.cve.aliases.map((alias) => (
                      <Badge key={alias} variant="outline" className="font-mono text-[10px] border-border text-foreground">
                        {alias}
                      </Badge>
                    ))}
                  </div>
                )}
              </Card>

              {/* Remediation & Hardening Guidance */}
              <Card className="p-5 border-border bg-card">
                <div className="flex items-center gap-2 text-[13px] font-semibold text-foreground mb-3">
                  <ShieldCheck className="size-4 text-emerald-400" />
                  <h3>Remediation Guidance & Patch Advisory</h3>
                </div>
                <div className="space-y-2.5">
                  {dossier.cve.remediation.map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2.5 text-[12px] text-muted-foreground">
                      <CheckCircle2 className="size-4 shrink-0 text-emerald-400 mt-0.5" />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </Card>
            </div>
          )}

          {activeTab === 'telemetry' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-[13px] font-semibold text-foreground">
                  <Terminal className="size-4 text-primary" />
                  <h3>Raw Telemetry Payload & Artifacts</h3>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={copyPayload}
                  className="h-7 text-[11px] gap-1.5"
                >
                  {copied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
                  {copied ? 'Copied' : 'Copy JSON'}
                </Button>
              </div>

              <div className="rounded-lg border border-border bg-secondary/30 p-4 font-mono text-[11.5px] overflow-x-auto text-foreground">
                <pre>{JSON.stringify(dossier.telemetryEvidence.rawPayload, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>

        {/* Footer SOC Actions */}
        <div className="flex items-center justify-between border-t border-border bg-secondary/30 px-6 py-3.5">
          <div className="text-[11.5px] text-muted-foreground font-mono">
            Autonomous Active Defense: Ready for containment
          </div>

          <div className="flex items-center gap-2.5">
            <Link
              href={`/twin`}
              onClick={() => {
                if (dossier.targetAsset.id) {
                  useUI.getState().setSelectedNode(dossier.targetAsset.id);
                }
              }}
            >
              <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px]">
                <Server className="size-3.5 text-primary" /> Locate on Digital Twin
              </Button>
            </Link>
            <Link
              href={`/paths`}
              onClick={() => {
                if (dossier.pathId) {
                  useUI.getState().setActivePath(dossier.pathId);
                }
              }}
            >
              <Button variant="outline" size="sm" className="h-8 gap-1.5 text-[11.5px] border-border text-foreground hover:bg-secondary">
                <Route className="size-3.5" /> View Attack Paths
              </Button>
            </Link>
            <Button
              variant="destructive"
              size="sm"
              onClick={handleQuarantine}
              className="h-8 gap-1.5 text-[11.5px] font-semibold shadow-sm"
            >
              <Lock className="size-3.5" /> Quarantine Attacker IP ({dossier.attacker.ip})
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

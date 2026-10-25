'use client';

import { ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useFindingAnalysis } from '@/lib/soc/queries';
import type { Finding } from '@/types/soc';
import { CATEGORY_LABEL, fmtTime, socSeverityColor } from './meta';

export function FindingsFeed({
  items,
  selectedId,
  onSelect,
}: {
  items: Finding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (!items.length) {
    return <div className="py-6 text-center text-[11.5px] text-muted-foreground">No flagged requests.</div>;
  }
  return (
    <ul className="divide-y" role="listbox" aria-label="Flagged requests">
      {items.map((f) => (
        <li key={f.id}>
          <button
            role="option"
            aria-selected={f.id === selectedId}
            onClick={() => onSelect(f.id)}
            className={cn(
              'w-full px-2 py-1.5 text-left text-[11.5px] hover:bg-secondary/40',
              f.id === selectedId && 'bg-primary/10',
            )}
          >
            <div className="flex items-center gap-2">
              <span className="w-[56px] shrink-0 text-[10px] font-semibold" style={{ color: socSeverityColor(f.severity) }}>
                {f.severity}
              </span>
              <span className="flex-1 truncate font-medium">{CATEGORY_LABEL[f.category]}</span>
              <span className="font-mono text-[10px] text-muted-foreground">{fmtTime(f.ts)}</span>
            </div>
            <div className="mt-0.5 truncate pl-[64px] font-mono text-[10.5px] text-muted-foreground">
              {f.method ?? ''} {f.path ?? ''} · {f.sourceKey}
            </div>
          </button>
        </li>
      ))}
    </ul>
  );
}

export function AnalysisPanel({ findingId }: { findingId: string | null }) {
  const { data, isLoading, error } = useFindingAnalysis(findingId);

  if (!findingId) {
    return (
      <div className="py-10 text-center text-[11.5px] text-muted-foreground">
        Select a flagged request to see root-cause diagnostics and hardening guidance.
      </div>
    );
  }
  if (isLoading) return <div className="py-10 text-center text-[11.5px] text-muted-foreground">Analysing…</div>;
  if (error || !data) return <div className="py-10 text-center text-[11.5px] text-destructive">Analysis unavailable.</div>;

  const f = data.finding;
  return (
    <div className="space-y-4 text-[12px]">
      <div>
        <div className="mb-1 flex items-center gap-2">
          <span
            className="rounded px-1.5 py-0.5 text-[10px] font-semibold"
            style={{ color: socSeverityColor(f.severity), background: `color-mix(in srgb, ${socSeverityColor(f.severity)} 15%, transparent)` }}
          >
            {f.severity}
          </span>
          <span className="font-semibold">{CATEGORY_LABEL[f.category]}</span>
          <span className="font-mono text-[10.5px] text-muted-foreground">{f.ruleId}</span>
        </div>
        <dl className="grid grid-cols-[80px_1fr] gap-x-3 gap-y-1 text-[11px]">
          <dt className="text-muted-foreground">Request</dt>
          <dd className="font-mono">{f.method} {f.path}</dd>
          <dt className="text-muted-foreground">Source</dt>
          <dd className="font-mono">{f.sourceKey}</dd>
          <dt className="text-muted-foreground">Location</dt>
          <dd className="font-mono">{f.location}{f.field ? ` → ${f.field}` : ''}</dd>
          {f.evidence && (
            <>
              <dt className="text-muted-foreground">Evidence</dt>
              {/* Rendered as text (React escapes it) — never as HTML. */}
              <dd className="break-all rounded bg-secondary/60 px-1.5 py-1 font-mono text-[10.5px]">{f.evidence}</dd>
            </>
          )}
        </dl>
      </div>

      <section>
        <h4 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">Root cause</h4>
        <p className="leading-relaxed">{data.rootCause}</p>
      </section>

      <section>
        <h4 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">Potential impact</h4>
        <p className="leading-relaxed text-muted-foreground">{data.impact}</p>
      </section>

      <section>
        <h4 className="mb-2 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">
          Hardening recommendations
        </h4>
        <ol className="space-y-3">
          {data.recommendations.map((r, i) => (
            <li key={r.title} className="rounded-md border p-2.5">
              <div className="flex items-start gap-2">
                <span className="font-mono text-[10.5px] text-muted-foreground">{i + 1}.</span>
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{r.title}</div>
                  <p className="mt-0.5 text-[11.5px] text-muted-foreground">{r.detail}</p>
                  {r.snippet && (
                    <pre className="mt-2 overflow-x-auto rounded bg-background p-2 font-mono text-[10.5px] leading-relaxed">
                      <code>{r.snippet}</code>
                    </pre>
                  )}
                  {r.reference && (
                    <a
                      href={r.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mt-1.5 inline-flex items-center gap-1 text-[10.5px] text-primary hover:underline"
                    >
                      Reference <ExternalLink className="size-3" aria-hidden />
                    </a>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {data.relatedFindings.length > 0 && (
        <section>
          <h4 className="mb-1 text-[10.5px] font-semibold uppercase tracking-wide text-muted-foreground">
            Other findings from this source
          </h4>
          <ul className="space-y-0.5 text-[11px]">
            {data.relatedFindings.map((r) => (
              <li key={r.id} className="flex gap-2 font-mono text-muted-foreground">
                <span>{fmtTime(r.ts)}</span>
                <span>{CATEGORY_LABEL[r.category]}</span>
                <span className="truncate">{r.path}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

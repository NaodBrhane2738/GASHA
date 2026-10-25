// Deterministic request classification for the simulation. Mirrors the backend signatures in
// apps/api/app/detection/inspectors.py so the demo behaves like the real pipeline.

import type { FindingCategory, SocSeverity } from '@/types/soc';

export interface RawFinding {
  ruleId: string;
  category: FindingCategory;
  severity: SocSeverity;
  location: 'path' | 'query' | 'body';
  field?: string;
  evidence?: string;
  diagnostic: string;
}

interface Signature {
  ruleId: string;
  category: FindingCategory;
  severity: SocSeverity;
  pattern: RegExp;
  diagnostic: string;
}

const SIGNATURES: Signature[] = [
  {
    ruleId: 'RULE-INJ-002',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    pattern: /(\bunion\b[\s/*]+(all[\s/*]+)?select\b|;\s*(drop|delete|truncate|alter|insert|update)\b|\b(sleep|benchmark|pg_sleep)\s*\()/i,
    diagnostic:
      'Input contains SQL control syntax (UNION / stacked query / time-delay function). If concatenated into a query string the database would execute attacker-supplied SQL.',
  },
  {
    ruleId: 'RULE-INJ-003',
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    pattern: /(['"])\s*(or|and)\s+['"]?(\w+)['"]?\s*=\s*['"]?\3\b|(['"])\s*(--|#|\/\*)/i,
    diagnostic:
      "Input closes a string literal and appends a tautology or comment (e.g. ' OR 1=1 --), the classic pattern for bypassing WHERE clauses.",
  },
  {
    ruleId: 'RULE-TRV-001',
    category: 'PATH_TRAVERSAL',
    severity: 'HIGH',
    pattern: /(\.\.[/\\])|(%2e%2e(%2f|%5c|\/|\\))|(\/etc\/(passwd|shadow))/i,
    diagnostic:
      'Input contains relative path segments or system file paths. Used to build a filesystem path without canonicalisation it could escape the intended directory.',
  },
  {
    ruleId: 'RULE-XSS-001',
    category: 'XSS_PROBE',
    severity: 'MEDIUM',
    pattern: /(<\s*script\b|javascript\s*:|\bon(error|load|mouseover|focus)\s*=)/i,
    diagnostic:
      'Input contains executable HTML/JS markup. Rendered without contextual output encoding it would run script in other users’ browsers.',
  },
];

const excerpt = (v: string, m: RegExpExecArray) => {
  const start = Math.max(0, m.index - 30);
  return v.slice(start, start + 120).replace(/[^\x20-\x7e]/g, '�');
};

function scan(value: string, location: RawFinding['location'], field?: string): RawFinding[] {
  let decoded = value;
  try {
    decoded = decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    /* keep raw */
  }
  const out: RawFinding[] = [];
  const seen = new Set<string>();
  for (const s of SIGNATURES) {
    if (seen.has(s.category)) continue;
    const m = s.pattern.exec(decoded);
    if (m) {
      seen.add(s.category);
      out.push({ ruleId: s.ruleId, category: s.category, severity: s.severity, location, field, evidence: excerpt(decoded, m), diagnostic: s.diagnostic });
    }
  }
  return out;
}

export function inspect(path: string, query: Record<string, string> = {}, body: Record<string, string> = {}) {
  return [
    ...scan(path, 'path'),
    ...Object.entries(query).flatMap(([k, v]) => scan(v, 'query', k)),
    ...Object.entries(body).flatMap(([k, v]) => scan(v, 'body', k)),
  ];
}

export const SEVERITY_RANK: Record<SocSeverity, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

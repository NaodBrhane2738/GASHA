/**
 * ==============================================================================
 * FILE: packages/telemetry-sdk/typescript/index.ts
 * ROLE / OWNERSHIP: Shared Telemetry SDK Maintainers
 * OBJECTIVE: High-performance, non-blocking telemetry emitter and middleware
 *            for Node.js, Express, Fastify, and Next.js applications.
 * TOOLS & LIBRARIES: TypeScript 5.x, Node.js Fetch API / HTTP
 * ==============================================================================
 */

import { TelemetryEvent, TelemetryEventType, TelemetryEventPayload } from '@gasha/contracts';

export const REDACTED_VALUE = '[REDACTED]';

const SENSITIVE_KEY_PATTERNS: RegExp[] = [
  /^.*(pass(word)?|passwd).*$/i,
  /^.*(client_secret|client_key|private_key|privkey).*$/i,
  /^.*(secret).*$/i,
  /^.*(access_token|refresh_token|id_token|bearer_token|auth_token).*$/i,
  /^.*(cookie|set_cookie).*$/i,
  /^.*(api[_-]?key).*$/i,
  /^.*(credit[_-]?card|card[_-]?num(ber)?|cvv|cvc).*$/i,
];

const EXACT_SENSITIVE_KEYS = new Set<string>([
  'token',
  'authorization',
  'auth',
  'session_secret',
  'session_token',
  'signature',
  'sig',
  'pin',
  'credential',
  'credentials',
  'proxy-authorization',
]);

const PRESERVED_KEYS = new Set<string>([
  'session_id',
  'sessionid',
  'sessionId',
  'user_id',
  'userid',
  'userId',
  'auth_method',
  'auth_result',
  'action',
  'outcome',
  'target',
  'resource',
  'resourceAccessed',
  'endpoint',
  'path',
  'source_ip',
  'sourceip',
  'sourceIp',
  'client_id',
  'agent_id',
  'environment_id',
  'environmentId',
  'correlation_id',
  'correlationId',
  'event_id',
  'status_code',
  'http_status',
  'httpStatusCode',
  'http_method',
  'httpMethod',
]);

const JWT_PATTERN = /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/;

export function isSensitiveKey(key: string): boolean {
  if (typeof key !== 'string') return false;
  const trimmed = key.trim();
  const lower = trimmed.toLowerCase();
  if (PRESERVED_KEYS.has(trimmed) || PRESERVED_KEYS.has(lower)) {
    return false;
  }
  if (EXACT_SENSITIVE_KEYS.has(lower)) {
    return true;
  }
  return SENSITIVE_KEY_PATTERNS.some((pattern) => pattern.test(lower));
}

export function sanitizeValue(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    const lower = trimmed.toLowerCase();
    if (lower.startsWith('bearer ') && value.length > 7) {
      return 'Bearer [REDACTED]';
    }
    if (lower.startsWith('basic ') && value.length > 6) {
      return 'Basic [REDACTED]';
    }
    if (JWT_PATTERN.test(trimmed)) {
      return '[REDACTED_JWT]';
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item));
  }
  if (typeof value === 'object') {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (isSensitiveKey(k)) {
        sanitizedObj[k] = REDACTED_VALUE;
      } else {
        sanitizedObj[k] = sanitizeValue(v);
      }
    }
    return sanitizedObj;
  }
  return value;
}

export function sanitizeMetadata(data: unknown): Record<string, unknown> {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return {};
  }
  return sanitizeValue(data) as Record<string, unknown>;
}

export function sanitizeHeaders(headers: Record<string, unknown>): Record<string, unknown> {
  if (!headers || typeof headers !== 'object') {
    return {};
  }
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (isSensitiveKey(k)) {
      result[k] = REDACTED_VALUE;
    } else {
      result[k] = sanitizeValue(v);
    }
  }
  return result;
}

export interface TelemetryClientConfig {
  endpoint: string;
  apiKey: string;
  environmentId?: string;
  serviceName?: string;
  batchSize?: number;
  flushIntervalMs?: number;
  maxQueueSize?: number;
  maxRetries?: number;
  timeoutMs?: number;
  trustedProxies?: string[];
  suppressedPaths?: string[];
}

export interface SDKMetrics {
  queuedCount: number;
  transmittedCount: number;
  droppedCount: number;
  errorCount: number;
  retryCount: number;
  lastFlushTime: string | null;
  isRunning: boolean;
}

const SQLI_PATTERN = /(\bunion\b.*\bselect\b|'|"|\b(select|insert|update|delete|drop|alter)\b.*--|--|\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+)/i;
const XSS_PATTERN = /(<script\b|javascript:|onerror=|onload=|eval\(|alert\(|<svg|<iframe)/i;
const PATH_TRAVERSAL_PATTERN = /(\.\.[\/\\]|%2e%2e[\/\\]|\/etc\/passwd|\/windows\/win\.ini)/i;

export class GashaTelemetryClient {
  private config: Required<TelemetryClientConfig>;
  private queue: TelemetryEvent[] = [];
  private timer: NodeJS.Timeout | null = null;
  private isShuttingDown = false;
  private metrics: SDKMetrics = {
    queuedCount: 0,
    transmittedCount: 0,
    droppedCount: 0,
    errorCount: 0,
    retryCount: 0,
    lastFlushTime: null,
    isRunning: false,
  };

  constructor(config: TelemetryClientConfig) {
    this.config = {
      endpoint: config.endpoint || 'http://localhost:4000/api/v1/telemetry/ingest',
      apiKey: config.apiKey || '',
      environmentId: config.environmentId || 'env-prod',
      serviceName: config.serviceName || 'node-service',
      batchSize: Math.max(1, config.batchSize || 20),
      flushIntervalMs: Math.max(100, config.flushIntervalMs || 1000),
      maxQueueSize: Math.max(100, config.maxQueueSize || 2000),
      maxRetries: Math.max(0, config.maxRetries ?? 3),
      timeoutMs: Math.max(500, config.timeoutMs || 3000),
      trustedProxies: config.trustedProxies || ['127.0.0.1', '::1'],
      suppressedPaths: config.suppressedPaths || ['/health', '/metrics', '/favicon.ico'],
    };

    this.startWorker();
  }

  private startWorker(): void {
    if (this.timer) return;
    this.metrics.isRunning = true;
    this.timer = setInterval(() => {
      this.flush().catch((err) => {
        // Silently handled in flush, error logged to metrics
      });
    }, this.config.flushIntervalMs);

    // Unref timer so it does not prevent Node process from exiting
    if (this.timer.unref) {
      this.timer.unref();
    }
  }

  public getMetrics(): Readonly<SDKMetrics> {
    return { ...this.metrics };
  }

  public emit(eventType: TelemetryEventType, payload: TelemetryEventPayload): void {
    if (this.isShuttingDown) return;

    // Sanitize payload metadata defense-in-depth
    const cleanPayload: TelemetryEventPayload = {
      ...payload,
      metadata: payload.metadata ? sanitizeMetadata(payload.metadata) : undefined,
    };

    const event: TelemetryEvent = {
      id: `telem-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      schemaVersion: '1.0.0',
      eventType,
      timestamp: new Date().toISOString(),
      sourceService: this.config.serviceName,
      environmentId: this.config.environmentId,
      payload: cleanPayload,
    };

    if (this.queue.length >= this.config.maxQueueSize) {
      // Buffer saturated: drop oldest to accept freshest security telemetry
      this.queue.shift();
      this.metrics.droppedCount++;
    }

    this.queue.push(event);
    this.metrics.queuedCount++;

    if (this.queue.length >= this.config.batchSize) {
      // Trigger non-blocking async flush
      setImmediate(() => {
        this.flush().catch(() => {});
      });
    }
  }

  public async flush(): Promise<void> {
    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.config.batchSize);
    if (batch.length === 0) return;

    await this.transmitWithRetry(batch);
  }

  private async transmitWithRetry(batch: TelemetryEvent[]): Promise<void> {
    let attempt = 0;
    const body = JSON.stringify({ events: batch });

    while (attempt <= this.config.maxRetries) {
      attempt++;
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

        const response = await fetch(this.config.endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-GASHA-TELEMETRY-KEY': this.config.apiKey,
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
          body,
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (response.status >= 200 && response.status < 300) {
          this.metrics.transmittedCount += batch.length;
          this.metrics.lastFlushTime = new Date().toISOString();
          return;
        }

        if (response.status >= 400 && response.status < 500) {
          // Client configuration or schema error - do not retry endlessly
          this.metrics.errorCount += batch.length;
          return;
        }

        // Server error (5xx) - eligible for retry
        this.metrics.retryCount++;
      } catch (err) {
        this.metrics.retryCount++;
      }

      if (attempt <= this.config.maxRetries) {
        const backoffMs = Math.min(2000, 200 * Math.pow(2, attempt - 1));
        await new Promise((res) => setTimeout(res, backoffMs));
      }
    }

    // Exhausted retries
    this.metrics.errorCount += batch.length;
    this.metrics.droppedCount += batch.length;
  }

  public async shutdown(timeoutMs = 5000): Promise<void> {
    this.isShuttingDown = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.metrics.isRunning = false;

    const startTime = Date.now();
    while (this.queue.length > 0 && Date.now() - startTime < timeoutMs) {
      await this.flush();
    }
  }

  // Developer Convenience Emitters
  public authFailure(details: {
    userId?: string;
    sourceIp?: string;
    reason?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('AUTH_FAILURE', {
      userId: details.userId,
      sourceIp: details.sourceIp,
      action: 'LOGIN',
      outcome: 'FAILURE',
      metadata: {
        reason: details.reason || 'Authentication failed',
        ...(details.metadata || {}),
      },
    });
  }

  public authSuccess(details: {
    userId: string;
    sourceIp?: string;
    sessionId?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('AUTH_SUCCESS', {
      userId: details.userId,
      sourceIp: details.sourceIp,
      sessionId: details.sessionId,
      action: 'LOGIN',
      outcome: 'SUCCESS',
      metadata: details.metadata || {},
    });
  }

  public httpRequest(details: {
    httpMethod: string;
    httpPath: string;
    httpStatusCode: number;
    latencyMs?: number;
    sourceIp?: string;
    observedPeerIp?: string;
    userAgent?: string;
    userId?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('HTTP_REQUEST', {
      httpMethod: details.httpMethod,
      httpPath: details.httpPath,
      httpStatusCode: details.httpStatusCode,
      latencyMs: details.latencyMs,
      sourceIp: details.sourceIp,
      observedPeerIp: details.observedPeerIp,
      userAgent: details.userAgent,
      userId: details.userId,
      metadata: details.metadata || {},
    });
  }

  public suspiciousRequest(details: {
    httpMethod: string;
    httpPath: string;
    patternType: string;
    matchedPattern?: string;
    sourceIp?: string;
    observedPeerIp?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('SUSPICIOUS_REQUEST', {
      httpMethod: details.httpMethod,
      httpPath: details.httpPath,
      sourceIp: details.sourceIp,
      observedPeerIp: details.observedPeerIp,
      action: 'INTRUSION_PROBE',
      outcome: 'DETECTED',
      metadata: {
        patternType: details.patternType,
        matchedPattern: details.matchedPattern,
        ...(details.metadata || {}),
      },
    });
  }

  public resourceAccess(details: {
    userId?: string;
    resource: string;
    action: string;
    outcome?: string;
    sourceIp?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('RESOURCE_ACCESS', {
      userId: details.userId,
      resourceAccessed: details.resource,
      action: details.action,
      outcome: details.outcome || 'ALLOWED',
      sourceIp: details.sourceIp,
      metadata: details.metadata || {},
    });
  }

  public privilegeChange(details: {
    targetUserId: string;
    actorUserId?: string;
    oldRole?: string;
    newRole: string;
    sourceIp?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('PRIVILEGE_CHANGE', {
      userId: details.targetUserId,
      action: 'ROLE_MODIFICATION',
      outcome: 'SUCCESS',
      sourceIp: details.sourceIp,
      metadata: {
        actorUserId: details.actorUserId,
        oldRole: details.oldRole,
        newRole: details.newRole,
        ...(details.metadata || {}),
      },
    });
  }

  public outboundConnection(details: {
    targetHost: string;
    targetPort: number;
    protocol?: string;
    metadata?: Record<string, unknown>;
  }): void {
    this.emit('OUTBOUND_CONNECTION', {
      resourceAccessed: `${details.targetHost}:${details.targetPort}`,
      action: 'EGRESS_CONNECT',
      outcome: 'INITIATED',
      metadata: {
        protocol: details.protocol || 'TCP',
        ...(details.metadata || {}),
      },
    });
  }

  /**
   * Express / Connect compatible HTTP middleware.
   * Intercepts incoming requests, extracts peer IP with trusted proxy attribution,
   * performs passive intrusion detection, and captures latency non-blockingly.
   */
  public expressMiddleware() {
    return (req: any, res: any, next: any) => {
      const urlPath = req.path || req.url || '/';

      // Suppress noisy heartbeat or self-telemetry paths
      if (
        this.config.suppressedPaths.some((p) => urlPath.startsWith(p)) ||
        urlPath.includes('/api/v1/telemetry')
      ) {
        return next();
      }

      const startTime = process.hrtime();
      const directPeer = req.socket?.remoteAddress || req.connection?.remoteAddress || '127.0.0.1';

      // Resolve source IP based on trusted proxies
      let sourceIp = directPeer;
      const isTrusted = this.config.trustedProxies.includes(directPeer);
      if (isTrusted) {
        const forwarded = req.headers['x-forwarded-for'];
        if (forwarded) {
          const firstIp = (Array.isArray(forwarded) ? forwarded[0] : forwarded).split(',')[0].trim();
          if (firstIp) sourceIp = firstIp;
        } else if (req.headers['x-real-ip']) {
          sourceIp = String(req.headers['x-real-ip']).trim();
        }
      }

      const method = req.method || 'GET';
      const userAgent = req.headers['user-agent'] || 'unknown';

      // Passive intrusion probe detection on query string & path
      const checkTarget = `${urlPath} ${req.originalUrl || ''} ${JSON.stringify(req.query || {})}`;
      let detectedProbeType: string | null = null;

      if (SQLI_PATTERN.test(checkTarget)) {
        detectedProbeType = 'SQL_INJECTION_PROBE';
      } else if (XSS_PATTERN.test(checkTarget)) {
        detectedProbeType = 'CROSS_SITE_SCRIPTING_PROBE';
      } else if (PATH_TRAVERSAL_PATTERN.test(checkTarget)) {
        detectedProbeType = 'PATH_TRAVERSAL_PROBE';
      }

      if (detectedProbeType) {
        this.suspiciousRequest({
          httpMethod: method,
          httpPath: urlPath,
          patternType: detectedProbeType,
          sourceIp,
          observedPeerIp: directPeer,
        });
      }

      // Record transaction on finish event
      res.on('finish', () => {
        const diff = process.hrtime(startTime);
        const latencyMs = (diff[0] * 1e9 + diff[1]) / 1e6;

        this.httpRequest({
          httpMethod: method,
          httpPath: urlPath,
          httpStatusCode: res.statusCode || 200,
          latencyMs: Math.round(latencyMs * 100) / 100,
          sourceIp,
          observedPeerIp: directPeer,
          userAgent: String(userAgent),
          userId: req.user?.id || req.userId,
        });
      });

      next();
    };
  }
}

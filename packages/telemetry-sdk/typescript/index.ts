/**
 * ==============================================================================
 * FILE: packages/telemetry-sdk/typescript/index.ts
 * ROLE / OWNERSHIP: Shared Telemetry SDK Maintainers
 * OBJECTIVE: Provide high-performance, non-blocking telemetry emitter for Node.js / Express / Next.js.
 * TOOLS & LIBRARIES: TypeScript 5.x, Fetch API / Axios, batch queue
 * KEY FEATURES / FUNCTIONS TO IMPLEMENT:
 *   - class GashaTelemetryClient:
 *       - constructor(config: TelemetryClientConfig)
 *       - emit(eventType: TelemetryEventType, payload: TelemetryEventPayload): Promise<void>
 *       - flush(): Promise<void>
 *       - middleware(): Express / Next.js middleware automatically intercepting requests
 * EXPECTED RESULTS / BEHAVIOR:
 *   - Buffers events, flushes asynchronously on batch size or timer, handles network retries.
 * ==============================================================================
 */

import { TelemetryEvent, TelemetryEventType, TelemetryEventPayload } from '@gasha/contracts';

export interface TelemetryClientConfig {
  endpoint: string;
  apiKey: string;
  environmentId: string;
  serviceName: string;
  batchSize?: number;
  flushIntervalMs?: number;
}

export class GashaTelemetryClient {
  private config: TelemetryClientConfig;
  private queue: TelemetryEvent[] = [];

  constructor(config: TelemetryClientConfig) {
    this.config = config;
  }

  public async emit(eventType: TelemetryEventType, payload: TelemetryEventPayload): Promise<void> {
    const event: TelemetryEvent = {
      id: `telem-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      eventType,
      timestamp: new Date().toISOString(),
      sourceService: this.config.serviceName,
      environmentId: this.config.environmentId,
      payload
    };
    this.queue.push(event);
    if (this.queue.length >= (this.config.batchSize || 20)) {
      await this.flush();
    }
  }

  public async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const batch = [...this.queue];
    this.queue = [];
    try {
      await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.config.apiKey}`
        },
        body: JSON.stringify({ events: batch })
      });
    } catch (err) {
      console.error('[GASHA Telemetry SDK] Flush failed:', err);
    }
  }
}

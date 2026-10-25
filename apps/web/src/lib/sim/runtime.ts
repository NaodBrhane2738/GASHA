'use client';

// Runs the simulation in exactly one browser tab (the leader, elected with the Web Locks API)
// and mirrors its state to every other tab over BroadcastChannel. This lets the sandbox store
// and the SOC dashboard sit side by side in two windows and stay perfectly in sync.

import { create } from 'zustand';
import { Engine, type ScenarioId, type SimResult, type SimState } from './engine';
import type { Product } from './seed';

export type Command =
  | { type: 'scenario'; id: ScenarioId }
  | { type: 'autopilot'; on: boolean }
  | { type: 'traffic'; on: boolean }
  | { type: 'store'; kind: 'search' | 'login' | 'product' | 'cart'; args: Record<string, string> }
  | { type: 'approve'; id: string }
  | { type: 'reject'; id: string }
  | { type: 'release'; ip: string }
  | { type: 'reset' };

export type StoreResult = SimResult & { products?: Product[] };

type Msg =
  | { t: 'snapshot'; state: SimState }
  | { t: 'hello' }
  | { t: 'cmd'; id: string; cmd: Command }
  | { t: 'reply'; id: string; result: unknown };

interface SimStore {
  state: SimState | null;
  leader: boolean;
}

export const useSim = create<SimStore>(() => ({ state: null, leader: false }));

const STORAGE_KEY = 'gasha.sim.v2';
const CHANNEL = 'gasha-sim';

let started = false;
let engine: Engine | null = null;
let channel: BroadcastChannel | null = null;
const pending = new Map<string, (r: unknown) => void>();
let publishTimer: ReturnType<typeof setTimeout> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;
let lastSaved = 0;

function exec(cmd: Command): unknown {
  const e = engine!;
  switch (cmd.type) {
    case 'scenario':
      e.runScenario(cmd.id);
      return true;
    case 'autopilot':
      e.S.autopilot = cmd.on;
      return true;
    case 'traffic':
      e.S.traffic = cmd.on;
      return true;
    case 'store':
      return e.storeRequest(cmd.kind, cmd.args);
    case 'approve':
      return e.approve(cmd.id);
    case 'reject':
      return e.reject(cmd.id);
    case 'release':
      return e.release(cmd.ip);
    case 'reset':
      e.stop();
      engine = new Engine();
      engine.onChange = publish;
      return true;
  }
}

function publishNow() {
  if (publishTimer) {
    clearTimeout(publishTimer);
    publishTimer = null;
  }
  if (!engine) return;
  const snap = structuredClone(engine.S);
  useSim.setState({ state: snap });
  channel?.postMessage({ t: 'snapshot', state: snap } satisfies Msg);
  if (Date.now() - lastSaved > 3000) {
    lastSaved = Date.now();
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(snap));
    } catch {
      /* storage unavailable or full */
    }
  }
}

/** Coalesces bursts of changes (e.g. a scraper scenario) into ~7 snapshots per second. */
function publish() {
  if (!publishTimer) publishTimer = setTimeout(publishNow, 150);
}

function restore(): SimState | null {
  const mirrored = useSim.getState().state;
  if (mirrored) return structuredClone(mirrored);
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as SimState;
    return s.v === 2 && Date.now() - s.now < 10 * 60_000 ? s : null;
  } catch {
    return null;
  }
}

function becomeLeader() {
  if (engine) return;
  const prior = restore();
  engine = new Engine(prior ?? undefined);
  if (prior) engine.catchUp();
  engine.onChange = publish;
  useSim.setState({ leader: true });
  publishNow();
  tickTimer = setInterval(() => {
    engine?.tick();
    publish();
  }, 1000);
}

function demote() {
  if (tickTimer) clearInterval(tickTimer);
  tickTimer = null;
  engine?.stop();
  engine = null;
  useSim.setState({ leader: false });
}

/**
 * Leadership follows the visible tab: hidden tabs have their timers throttled by the browser,
 * so a background leader would make the visible dashboard stall. A tab that becomes visible
 * steals the lock (carrying the mirrored state across); the previous leader steps down.
 */
function requestLeadership(steal: boolean) {
  navigator.locks
    .request('gasha-sim-leader', { steal }, () => {
      becomeLeader();
      return new Promise<void>(() => {});
    })
    .catch(() => {
      demote();
      requestLeadership(false);
    });
}

export function startSimulation() {
  if (started || typeof window === 'undefined') return;
  started = true;

  if ('BroadcastChannel' in window) {
    channel = new BroadcastChannel(CHANNEL);
    channel.onmessage = (ev: MessageEvent<Msg>) => {
      const m = ev.data;
      if (m.t === 'snapshot' && !engine) useSim.setState({ state: m.state });
      else if (m.t === 'hello' && engine) publishNow();
      else if (m.t === 'cmd' && engine) {
        const result = exec(m.cmd);
        publishNow();
        channel?.postMessage({ t: 'reply', id: m.id, result } satisfies Msg);
      } else if (m.t === 'reply') {
        pending.get(m.id)?.(m.result);
        pending.delete(m.id);
      }
    };
    channel.postMessage({ t: 'hello' } satisfies Msg);
  }

  if ('locks' in navigator) {
    requestLeadership(document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible' && !engine) requestLeadership(true);
    });
  } else {
    becomeLeader();
  }
}

/** Sends a command to the leader tab (or runs it locally if this tab is the leader). */
export function sendCommand<T = unknown>(cmd: Command): Promise<T> {
  if (engine) {
    const r = exec(cmd) as T;
    publishNow();
    return Promise.resolve(r);
  }
  const id = Math.random().toString(36).slice(2);
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error('Simulation leader did not respond'));
    }, 4000);
    pending.set(id, (r) => {
      clearTimeout(timer);
      resolve(r as T);
    });
    channel?.postMessage({ t: 'cmd', id, cmd } satisfies Msg);
  });
}

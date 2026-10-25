'use client';

// Demo access gate for the presentation build. It keeps the console behind a login screen;
// it is not a security boundary (all data in this build is simulated and client-side).

import { useSyncExternalStore } from 'react';

export const DEMO_USERNAME = 'admin';
export const DEMO_PASSWORD = 'admin123';
const KEY = 'gasha.session';

const listeners = new Set<() => void>();

function read(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function signIn(username: string, password: string): boolean {
  if (username.trim() !== DEMO_USERNAME || password !== DEMO_PASSWORD) return false;
  try {
    sessionStorage.setItem(KEY, username.trim());
  } catch {
    /* storage unavailable: session lasts for this page only */
  }
  listeners.forEach((l) => l());
  return true;
}

export function signOut() {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
  listeners.forEach((l) => l());
}

/** undefined while hydrating, null when signed out, the username when signed in. */
export function useSession(): string | null | undefined {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    read,
    () => undefined,
  );
}

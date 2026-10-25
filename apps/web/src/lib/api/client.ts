import { isPolicyStatus, usePolicy } from '@/store/policy';
import type { PolicyProblem } from '@/types/soc';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public problem?: Partial<PolicyProblem>,
    public retryAfter?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }

  /** True for defensive policy responses (rate limited / locked / too large). */
  get isPolicy() {
    return isPolicyStatus(this.status);
  }
}

export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? '/api';

const TOKEN_KEY = 'gasha.accessToken';

/** Analyst bearer token, set by the sign-in flow. Kept out of URLs and cookies readable by JS elsewhere. */
export function getAccessToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function authHeaders(): Record<string, string> {
  const token = getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...authHeaders(), ...init?.headers },
    credentials: 'include',
  });
  if (!res.ok) {
    const text = await res.text();
    let problem: Partial<PolicyProblem> | undefined;
    try {
      problem = JSON.parse(text);
    } catch {
      /* non-JSON error body */
    }
    const retryHeader = res.headers.get('Retry-After');
    if (isPolicyStatus(res.status)) {
      usePolicy.getState().report(res.status, problem ?? {}, retryHeader);
    }
    throw new ApiError(
      res.status,
      problem?.detail ?? text,
      problem,
      retryHeader ? Number(retryHeader) : undefined,
    );
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

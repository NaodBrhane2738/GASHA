export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export function getBaseApiUrl(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol;
    const hostname = window.location.hostname;
    return `${protocol}//${hostname}:4000/api/v1`;
  }
  return 'http://127.0.0.1:4000/api/v1';
}

let authToken: string | null = null;
let authPromise: Promise<string | null> | null = null;

async function getAuthToken(): Promise<string | null> {
  if (authToken) return authToken;
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem('gasha_token');
    if (saved) {
      authToken = saved;
      return saved;
    }
  }

  if (authPromise) return authPromise;

  authPromise = (async () => {
    try {
      const base = getBaseApiUrl();
      const res = await fetch(`${base}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: process.env.NEXT_PUBLIC_API_USER ?? 'operator',
          password: process.env.NEXT_PUBLIC_API_PASSWORD ?? 'OperatorSecure2026!',
          environmentId: process.env.NEXT_PUBLIC_API_ENV ?? 'env-prod',
        }),
      });
      if (res.ok) {
        const data = await res.json();
        const token = data.accessToken || data.access_token;
        if (token) {
          authToken = token;
          if (typeof window !== 'undefined') {
            localStorage.setItem('gasha_token', token);
          }
          return authToken;
        }
      }
    } catch {
      // In offline or fallback, proceed without token
    }
    return null;
  })();

  try {
    return await authPromise;
  } finally {
    authPromise = null;
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getAuthToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string>),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const base = getBaseApiUrl();
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  const res = await fetch(`${base}${cleanPath}`, {
    ...init,
    headers,
    credentials: 'include',
  });

  if (!res.ok) {
    if (res.status === 401 && typeof window !== 'undefined') {
      localStorage.removeItem('gasha_token');
      authToken = null;
    }
    throw new ApiError(res.status, await res.text());
  }
  return res.json() as Promise<T>;
}

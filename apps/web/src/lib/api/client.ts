export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export function getBaseApiUrl(): string {
  if (typeof window !== 'undefined') {
    return '/api/v1';
  }
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  return 'http://127.0.0.1:4000/api/v1';
}

let authToken: string | null = null;

export function getStoredToken(): string | null {
  if (authToken) return authToken;
  if (typeof window !== 'undefined') {
    const saved = localStorage.getItem('gasha_token');
    if (saved) {
      authToken = saved;
      return saved;
    }
  }
  return null;
}

export function getStoredUser(): { username: string; role: string; environmentId: string } | null {
  if (typeof window !== 'undefined') {
    try {
      const saved = localStorage.getItem('gasha_user');
      if (saved) return JSON.parse(saved);
    } catch {
      return null;
    }
  }
  return null;
}

export async function loginUser(
  username: string,
  password: string,
  environmentId = 'env-prod'
): Promise<{ success: boolean; error?: string }> {
  try {
    const base = getBaseApiUrl();
    const res = await fetch(`${base}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: username.trim(),
        password,
        environmentId,
      }),
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      return { success: false, error: errData.detail || 'Invalid username or password' };
    }

    const data = await res.json();
    const token = data.accessToken || data.access_token;
    if (token) {
      authToken = token;
      if (typeof window !== 'undefined') {
        localStorage.setItem('gasha_token', token);
        localStorage.setItem(
          'gasha_user',
          JSON.stringify({
            username: username.trim(),
            role: data.role || 'security_analyst',
            environmentId: data.environmentId || environmentId,
          })
        );
      }
      return { success: true };
    }
    return { success: false, error: 'Authentication failed: no token returned' };
  } catch (err: any) {
    return { success: false, error: err?.message || 'Network error reaching authentication service' };
  }
}

export function logoutUser() {
  authToken = null;
  if (typeof window !== 'undefined') {
    localStorage.removeItem('gasha_token');
    localStorage.removeItem('gasha_user');
    window.location.href = '/login';
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getStoredToken();
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
      if (!window.location.pathname.startsWith('/login')) {
        window.location.href = '/login';
      }
    }
    throw new ApiError(res.status, await res.text());
  }
  return res.json() as Promise<T>;
}

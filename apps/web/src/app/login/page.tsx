'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Lock, ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { DEMO_PASSWORD, DEMO_USERNAME, signIn, useSession } from '@/lib/auth';

export default function LoginPage() {
  const router = useRouter();
  const session = useSession();
  const [username, setUsername] = useState(DEMO_USERNAME);
  const [password, setPassword] = useState(DEMO_PASSWORD);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (session) router.replace('/soc');
  }, [session, router]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    setTimeout(() => {
      if (signIn(username, password)) router.replace('/soc');
      else {
        setError('Invalid username or password.');
        setBusy(false);
      }
    }, 450);
  };

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-4">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-60"
        style={{
          background:
            'radial-gradient(600px circle at 20% 20%, hsl(var(--primary) / 0.18), transparent 60%), radial-gradient(500px circle at 80% 80%, hsl(var(--critical) / 0.12), transparent 60%)',
        }}
      />
      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex size-10 items-center justify-center rounded-lg bg-primary/15 text-primary">
            <ShieldCheck className="size-5" />
          </div>
          <div>
            <div className="text-[16px] font-semibold leading-tight">Gasha AEGIS</div>
            <div className="text-[12px] text-muted-foreground">Security Operations Console</div>
          </div>
        </div>

        <form onSubmit={submit} className="space-y-4 rounded-xl border bg-card/90 p-6 shadow-xl backdrop-blur">
          <div>
            <h1 className="text-[15px] font-semibold">Administrator sign in</h1>
            <p className="mt-1 text-[12px] text-muted-foreground">Demo credentials are pre-filled.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="username">Username</Label>
            <Input id="username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          {error && (
            <p role="alert" className="text-[12px] text-destructive">
              {error}
            </p>
          )}
          <Button type="submit" className="w-full" disabled={busy}>
            <Lock className="size-4" /> {busy ? 'Signing in…' : 'Sign in'}
          </Button>
          <p className="text-center text-[11px] text-muted-foreground">
            Demo: <span className="font-mono">{DEMO_USERNAME}</span> / <span className="font-mono">{DEMO_PASSWORD}</span>
          </p>
        </form>
      </div>
    </main>
  );
}

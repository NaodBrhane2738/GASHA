'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, Lock, User, KeyRound, AlertCircle, Sparkles, Terminal } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { loginUser } from '@/lib/api/client';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('analyst01');
  const [password, setPassword] = useState('agis');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setError('Please provide both username and password.');
      return;
    }

    setLoading(true);
    setError(null);

    const res = await loginUser(username, password);
    setLoading(false);

    if (res.success) {
      router.push('/twin');
      router.refresh();
    } else {
      setError(res.error || 'Authentication rejected. Verify credentials.');
    }
  };

  const setDemoCredentials = () => {
    setUsername('analyst01');
    setPassword('agis');
    setError(null);
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background p-4 overflow-hidden">
      {/* Background Cyber Grid Accent */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-primary/10 via-background to-background" />
      <div className="pointer-events-none absolute -top-40 -right-40 size-96 rounded-full bg-primary/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-40 -left-40 size-96 rounded-full bg-cyan-500/10 blur-3xl" />

      <Card className="relative z-10 w-full max-w-[420px] border-border bg-card/90 p-8 shadow-2xl backdrop-blur-xl">
        {/* Header Branding */}
        <div className="mb-6 flex flex-col items-center text-center">
          <div className="mb-3 flex size-12 items-center justify-center rounded-xl bg-primary/15 text-primary border border-primary/30 shadow-[0_0_20px_rgba(6,182,212,0.25)]">
            <Shield className="size-6 text-primary animate-pulse" />
          </div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-[17px] font-bold tracking-tight text-foreground">GASHA AEGIS</h1>
            <Badge variant="outline" className="border-primary/40 text-primary text-[10px] font-mono px-1.5 py-0">
              v1.0 CSOC
            </Badge>
          </div>
          <p className="text-[12px] text-muted-foreground">
            Graph-Adaptive Security & Autonomous Response
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-[12px] text-red-400">
            <AlertCircle className="size-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1.5 block text-[11.5px] font-medium text-muted-foreground">
              Analyst Identity
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst01"
                required
                className="w-full rounded-md border border-border bg-secondary/40 py-2 pl-9 pr-3 text-[13px] text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>

          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <label className="text-[11.5px] font-medium text-muted-foreground">
                Security Passkey
              </label>
              <span className="text-[10.5px] text-muted-foreground/80 font-mono">
                PBKDF2 Protected
              </span>
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password (agis)"
                required
                className="w-full rounded-md border border-border bg-secondary/40 py-2 pl-9 pr-3 text-[13px] text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none focus:ring-1 focus:ring-primary font-mono"
              />
            </div>
          </div>

          <Button
            type="submit"
            disabled={loading}
            className="w-full h-10 mt-2 font-medium text-[13px] shadow-md shadow-primary/20 transition-all hover:shadow-primary/30"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="size-3.5 rounded-full border-2 border-current border-t-transparent animate-spin" />
                Authenticating Session…
              </span>
            ) : (
              <span className="flex items-center justify-center gap-1.5">
                <KeyRound className="size-4" />
                Authenticate & Enter CSOC
              </span>
            )}
          </Button>
        </form>

        {/* Demo Quick-Fill Pill */}
        <div className="mt-5 pt-4 border-t border-border/80">
          <div className="flex items-center justify-between text-[11px] text-muted-foreground mb-2">
            <span className="flex items-center gap-1 font-mono text-[10.5px]">
              <Terminal className="size-3 text-primary" /> Default Credentials:
            </span>
            <button
              type="button"
              onClick={setDemoCredentials}
              className="text-primary hover:underline font-semibold flex items-center gap-1 text-[10.5px]"
            >
              <Sparkles className="size-3" /> Auto-fill
            </button>
          </div>
          <div className="flex items-center justify-between rounded bg-secondary/60 px-2.5 py-1.5 text-[11px] font-mono text-muted-foreground">
            <span>User: <strong className="text-foreground">analyst01</strong></span>
            <span>Password: <strong className="text-foreground">agis</strong></span>
          </div>
        </div>
      </Card>
    </div>
  );
}

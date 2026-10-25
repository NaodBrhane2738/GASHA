'use client';

import { useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { ExternalLink, LogOut, ShoppingBag } from 'lucide-react';
import { signOut, useSession } from '@/lib/auth';
import { useSim } from '@/lib/sim/runtime';
import { MONITORED_ASSET } from '@/lib/sim/seed';
import { Button } from '@/components/ui/button';

export function AuthGate({ children }: { children: React.ReactNode }) {
  const session = useSession();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (session === null) router.replace(`/login?next=${encodeURIComponent(pathname)}`);
  }, [session, router, pathname]);

  if (!session) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-[12px] text-muted-foreground">
        Verifying session…
      </div>
    );
  }
  return <>{children}</>;
}

export function ShellHeader() {
  const session = useSession();
  const router = useRouter();
  const ready = useSim((s) => !!s.state);
  const mitigations = useSim((s) => s.state?.mitigations.length ?? 0);

  return (
    <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2.5 sm:px-4">
      <Link href="/soc" className="flex items-center gap-2.5">
        <div className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary">
          <span className="text-[13px] font-bold">G</span>
        </div>
        <div>
          <div className="text-[13px] font-semibold leading-none">Gasha AEGIS</div>
          <div className="text-[10.5px] text-muted-foreground">Security Operations</div>
        </div>
      </Link>

      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground sm:gap-3">
        <span className="hidden items-center gap-1.5 rounded-md border px-2 py-1 md:flex" title="Monitored deployment (status simulated)">
          <span className="inline-block size-2 rounded-full bg-[hsl(var(--low))]" />
          <span className="font-mono">{MONITORED_ASSET}</span>
        </span>
        <span className="hidden items-center gap-1.5 sm:flex">
          <span
            className="inline-block size-2 rounded-full"
            style={{ background: ready ? (mitigations ? 'hsl(var(--high))' : 'hsl(var(--low))') : 'hsl(var(--medium))' }}
          />
          {ready ? (mitigations ? `${mitigations} active mitigation${mitigations > 1 ? 's' : ''}` : 'All clear') : 'Starting…'}
        </span>
        <Button asChild size="sm" variant="outline" className="h-7 gap-1.5 px-2 text-[11px]">
          <a href="/store" target="_blank" rel="noopener noreferrer">
            <ShoppingBag className="size-3.5" /> Demo store <ExternalLink className="size-3" />
          </a>
        </Button>
        {session && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 gap-1.5 px-2 text-[11px]"
            onClick={() => {
              signOut();
              router.replace('/login');
            }}
          >
            <LogOut className="size-3.5" /> <span className="hidden sm:inline">Sign out</span>
          </Button>
        )}
      </div>
    </header>
  );
}

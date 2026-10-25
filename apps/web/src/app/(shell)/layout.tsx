'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { LoopRail } from '@/components/loop/LoopRail';
import { AnalystDock } from '@/components/analyst/AnalystDock';
import { getStoredToken, getStoredUser, logoutUser } from '@/lib/api/client';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { User, LogOut, ShieldCheck } from 'lucide-react';

export default function ShellLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [mounted, setMounted] = useState(false);
  const [user, setUser] = useState<{ username: string; role: string; environmentId: string } | null>(null);

  useEffect(() => {
    setMounted(true);
    const token = getStoredToken();
    if (!token) {
      router.replace('/login');
    } else {
      setUser(getStoredUser() ?? { username: 'analyst01', role: 'security_analyst', environmentId: 'env-prod' });
    }
  }, [router]);

  if (!mounted) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-[12.5px] text-muted-foreground">
        <span className="size-3.5 rounded-full border-2 border-primary border-t-transparent animate-spin mr-2" />
        Validating session…
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="flex items-center justify-between border-b border-border bg-card/80 backdrop-blur-md px-4 py-2.5">
        <div className="flex items-center gap-2.5">
          <div className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary border border-primary/30">
            <span className="text-[13px] font-bold">G</span>
          </div>
          <div>
            <div className="text-[13px] font-semibold leading-none flex items-center gap-1.5">
              <span>Gasha AEGIS</span>
              <Badge variant="outline" className="text-[9.5px] font-mono border-primary/30 text-primary py-0 px-1">
                CSOC
              </Badge>
            </div>
            <div className="text-[10.5px] text-muted-foreground mt-0.5">Autonomous Security Operations</div>
          </div>
        </div>

        {/* Right side: User Identity & Logout */}
        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 rounded-full border border-border bg-secondary/50 px-3 py-1 text-[11px]">
            <ShieldCheck className="size-3.5 text-emerald-500" />
            <span className="text-muted-foreground font-mono">{user?.environmentId || 'env-prod'}</span>
            <span className="text-border">|</span>
            <User className="size-3 text-muted-foreground" />
            <span className="font-medium text-foreground">{user?.username || 'analyst01'}</span>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={logoutUser}
            className="h-7 gap-1.5 px-2.5 text-[11.5px] text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
          >
            <LogOut className="size-3.5" />
            <span>Sign out</span>
          </Button>
        </div>
      </header>

      <LoopRail />

      <main className="flex-1 overflow-hidden">{children}</main>

      <AnalystDock />
    </div>
  );
}

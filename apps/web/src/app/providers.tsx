'use client';

import { useEffect, useRef } from 'react';
import { toast } from 'sonner';
import { Toaster } from '@/components/ui/sonner';
import { startSimulation, useSim } from '@/lib/sim/runtime';

/** Toasts each newly dispatched SOC alert so the alert pipeline is visible on screen. */
function AlertToasts() {
  const alerts = useSim((s) => s.state?.alerts);
  const seen = useRef<Set<string> | null>(null);

  useEffect(() => {
    if (!alerts) return;
    if (!seen.current) {
      seen.current = new Set(alerts.map((a) => a.id));
      return;
    }
    for (const a of [...alerts].reverse()) {
      if (seen.current.has(a.id)) continue;
      seen.current.add(a.id);
      toast.error(a.subject, { description: `Alert emailed to ${a.to}` });
    }
  }, [alerts]);

  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    startSimulation();
  }, []);

  return (
    <>
      {children}
      <AlertToasts />
      <Toaster position="bottom-right" theme="dark" richColors />
    </>
  );
}

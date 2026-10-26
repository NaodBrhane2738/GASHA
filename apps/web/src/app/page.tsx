'use client';

import { useEffect, useState } from 'react';
import { loginUser } from '@/lib/api/client';

export default function Home() {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const enterDashboard = async () => {
      const result = await loginUser('analyst01', 'agis');
      if (cancelled) return;
      if (result.success) {
        window.location.replace('/twin');
      } else {
        setError(result.error || 'Could not start the GASHA dashboard.');
      }
    };

    void enterDashboard();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="flex min-h-screen items-center justify-center bg-background text-muted-foreground text-[13px]">
      <div className="flex flex-col items-center gap-3">
        <span className="size-3 border-2 border-primary border-t-transparent animate-spin rounded-full" />
        <span>{error || 'Opening GASHA dashboard…'}</span>
      </div>
    </main>
  );
}

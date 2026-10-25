'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useState, useEffect } from 'react';
import { Toaster } from '@/components/ui/sonner';
import { ApiError } from '@/lib/api/client';

export function Providers({ children }: { children: React.ReactNode }) {
  const [qc] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            refetchOnWindowFocus: false,
            // Never hammer a server that is rate limiting or has locked us out.
            retry: (count, err) => !(err instanceof ApiError && err.isPolicy) && count < 1,
          },
        },
      }),
  );

  // Start MSW only in the browser during dev
  useEffect(() => {
    if (process.env.NODE_ENV !== 'development') return;
    if (typeof window === 'undefined') return;
    let cancelled = false;
    (async () => {
      const { worker } = await import('@/lib/mock/browser');
      await worker.start({ onUnhandledRequest: 'bypass' });
      if (cancelled) worker.stop();
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <QueryClientProvider client={qc}>
      {children}
      <Toaster position="bottom-right" theme="dark" />
    </QueryClientProvider>
  );
}
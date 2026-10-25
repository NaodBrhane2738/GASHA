'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
  const router = useRouter();

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('gasha_token') : null;
    if (token) {
      router.replace('/twin');
    } else {
      router.replace('/login');
    }
  }, [router]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background text-muted-foreground text-[13px]">
      <div className="flex items-center gap-2">
        <span className="size-3 rounded-full border-2 border-primary border-t-transparent animate-spin" />
        <span>Initializing Security Operations…</span>
      </div>
    </div>
  );
}

'use client';

import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ShieldCheck } from 'lucide-react';

export default function ConnectPage() {
  const onConnect = () => {
    window.location.href = '/api/auth/vercel/start';
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <Card className="w-[400px] p-6">
        <div className="mb-4 flex items-center gap-2">
          <ShieldCheck className="size-5 text-primary" />
          <h1 className="text-[15px] font-semibold">Connect Gasha to Vercel</h1>
        </div>
        <p className="mb-4 text-[12.5px] text-muted-foreground">
          Gasha will read project and deployment metadata to build a digital twin. Read-only scope.
        </p>
        <Button className="w-full" onClick={onConnect}>
          Authorize with Vercel
        </Button>
        <p className="mt-3 text-center text-[10.5px] text-muted-foreground">
          OAuth 2.0 · OIDC · revocable any time
        </p>
      </Card>
    </div>
  );
}
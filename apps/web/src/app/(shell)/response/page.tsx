'use client';

import { useResponses } from '@/lib/api/queries';
import { ActionCard } from '@/components/response/ActionCard';

export default function ResponsePage() {
  const { data } = useResponses();
  const proposed = data?.filter((r) => r.state === 'proposed') ?? [];
  const history = data?.filter((r) => r.state !== 'proposed') ?? [];

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4">
      <h2 className="mb-4 text-[13px] font-semibold">Controlled Response</h2>

      <div className="mb-6">
        <div className="mb-2 text-[11px] uppercase tracking-wide text-muted-foreground">
          Awaiting approval ({proposed.length})
        </div>
        <div className="space-y-2">
          {proposed.map((a) => (
            <ActionCard key={a.id} action={a} />
          ))}
        </div>
      </div>

      <div>
        <div className="mb-2 text-[11px] uppercase tracking-wide text-muted-foreground">
          History
        </div>
        <div className="space-y-2">
          {history.map((a) => (
            <ActionCard key={a.id} action={a} />
          ))}
        </div>
      </div>
    </div>
  );
}
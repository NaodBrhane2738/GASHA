'use client';

import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import { cn } from '@/lib/utils';

export function RiskDelta({ before, after }: { before: number; after?: number }) {
  if (after === undefined) return null;
  const delta = after - before;
  const Icon = delta === 0 ? Minus : delta < 0 ? ArrowDownRight : ArrowUpRight;
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-mono',
        delta < 0 && 'bg-[hsl(var(--low))]/15 text-[hsl(var(--low))]',
        delta > 0 && 'bg-[hsl(var(--critical))]/15 text-[hsl(var(--critical))]',
        delta === 0 && 'bg-secondary text-muted-foreground',
      )}
    >
      <Icon className="size-3" />
      {delta > 0 ? '+' : ''}
      {delta}
    </span>
  );
}
import type { RiskSnapshot } from '@/types/domain';

const now = Date.now();
export const riskFixture: RiskSnapshot[] = Array.from({ length: 24 }).map((_, i) => {
  const hour = 23 - i;
  const base = 45 + Math.sin(i / 3) * 8 + (i < 6 ? 20 : 0);
  return {
    ts: new Date(now - hour * 3_600_000).toISOString(),
    score: Math.round(Math.min(92, Math.max(28, base))),
    openPaths: 3 + (i < 6 ? 2 : 0),
    openIncidents: i < 3 ? 2 : 1,
  };
});
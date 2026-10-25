'use client';

import { usePaths, useRisk, useTwin, useIncidents } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { RiskGauge } from '@/components/risk/RiskGauge';
import { RiskSparkline } from '@/components/risk/RiskSparkline';

export default function RiskPage() {
  const { data } = useRisk();
  const { data: twin } = useTwin();
  const { data: paths } = usePaths();
  const { data: incidents } = useIncidents();
  const latest = data?.[data.length - 1];
  const first = data?.[0];
  const score = latest?.score ?? 0;
  const delta = latest && first ? latest.score - first.score : 0;

  const attacked = twin?.nodes.filter((n) => n.metadata?.status === 'under-attack').length ?? 0;
  const crownJewels = twin?.nodes.filter((n) => n.isCrownJewel).length ?? 0;
  const exploitable = twin?.edges.filter((e) => e.exploitable).length ?? 0;
  const contained = incidents?.filter((i) => i.riskAfter !== undefined && i.riskAfter < i.riskBefore).length ?? 0;

  return (
    <div className="h-full overflow-y-auto p-3 sm:p-4 lg:h-[calc(100vh-100px)]">
      <h2 className="mb-1 text-[13px] font-semibold">Dynamic Risk Engine</h2>
      <p className="mb-4 text-[11px] text-muted-foreground">
        Recalculated every 10 s from open attack paths, incident severity and containment state
      </p>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="flex flex-col items-center justify-center p-6">
          <RiskGauge score={score} />
          <div className="mt-3 text-[11.5px] text-muted-foreground">Current composite risk</div>
          <div className="mt-1 font-mono text-[11px]" style={{ color: delta > 0 ? 'hsl(var(--high))' : 'hsl(var(--low))' }}>
            {delta > 0 ? '▲' : delta < 0 ? '▼' : '•'} {Math.abs(delta)} pts over 10 min
          </div>
        </Card>

        <Card className="p-4 lg:col-span-2">
          <div className="mb-2 text-[12px] font-medium">Last 10 minutes</div>
          {data && <RiskSparkline data={data} />}
          <p className="mt-2 text-[11px] text-muted-foreground">
            Spikes follow new incidents; drops follow automated locks and analyst-approved containment.
          </p>
        </Card>

        <Card className="p-4 lg:col-span-3">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
            <Stat label="Open paths" value={paths?.filter((p) => p.status === 'open').length ?? 0} />
            <Stat label="Mitigated paths" value={paths?.filter((p) => p.status === 'mitigated').length ?? 0} />
            <Stat label="Open incidents" value={latest?.openIncidents ?? 0} />
            <Stat label="Assets under attack" value={attacked} />
            <Stat label="Crown jewels" value={crownJewels} />
            <Stat label="Exploitable edges" value={exploitable} />
          </div>
          {contained > 0 && (
            <p className="mt-3 text-[11px] text-muted-foreground">{contained} incident(s) lowered risk after containment.</p>
          )}
        </Card>
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <div className="text-[10.5px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-mono text-[22px]">{value}</div>
    </div>
  );
}

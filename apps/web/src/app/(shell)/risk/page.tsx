'use client';

import { useRisk } from '@/lib/api/queries';
import { Card } from '@/components/ui/card';
import { RiskGauge } from '@/components/risk/RiskGauge';
import { RiskSparkline } from '@/components/risk/RiskSparkline';

export default function RiskPage() {
  const { data } = useRisk();
  const latest = data?.[data.length - 1];
  const score = latest?.score ?? 0;

  return (
    <div className="h-[calc(100vh-100px)] overflow-y-auto p-4">
      <h2 className="mb-4 text-[13px] font-semibold">Dynamic Risk Engine</h2>

      <div className="grid grid-cols-3 gap-4">
        <Card className="col-span-1 flex flex-col items-center justify-center p-6">
          <RiskGauge score={score} />
          <div className="mt-3 text-[11.5px] text-muted-foreground">Current composite risk</div>
        </Card>

        <Card className="col-span-2 p-4">
          <div className="mb-2 text-[12px] font-medium">Last 24 hours</div>
          {data && <RiskSparkline data={data} />}
        </Card>

        <Card className="col-span-3 p-4">
          <div className="grid grid-cols-4 gap-4">
            <Stat label="Open paths" value={latest?.openPaths ?? 0} />
            <Stat label="Open incidents" value={latest?.openIncidents ?? 0} />
            <Stat label="Critical assets" value={2} />
            <Stat label="Exploitable edges" value={5} />
          </div>
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
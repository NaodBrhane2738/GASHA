'use client';

import { Area, AreaChart, ResponsiveContainer, Tooltip, YAxis } from 'recharts';
import type { RiskSnapshot } from '@/types/domain';

export function RiskSparkline({ data }: { data: RiskSnapshot[] }) {
  return (
    <div className="h-[110px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data}>
          <defs>
            <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.4} />
              <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
            </linearGradient>
          </defs>
          <YAxis hide domain={[0, 100]} />
          <Tooltip
            contentStyle={{
              background: 'hsl(var(--popover))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 8,
              fontSize: 11,
            }}
            labelFormatter={(_, payload) =>
              payload?.[0]?.payload?.ts
                ? new Date(payload[0].payload.ts).toLocaleString()
                : ''
            }
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="hsl(var(--primary))"
            strokeWidth={2}
            fill="url(#riskFill)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
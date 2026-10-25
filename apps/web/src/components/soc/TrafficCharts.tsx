'use client';

import { useMemo } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import type { MetricsBucket } from '@/types/soc';
import { CHART, fmtTime } from './meta';

const BIN_SECONDS = 10;

const tooltipStyle = {
  background: 'hsl(var(--popover))',
  border: '1px solid hsl(var(--border))',
  borderRadius: 8,
  fontSize: 11,
  color: 'hsl(var(--foreground))',
};
const axisTick = { fontSize: 10, fill: 'hsl(var(--muted-foreground))' };

const SERIES = [
  { key: 'allowed', label: 'Allowed', color: CHART.allowed },
  { key: 'throttled', label: 'Throttled · 429', color: CHART.throttled },
  { key: 'locked', label: 'Locked · 423', color: CHART.locked },
] as const;

function bin(series: MetricsBucket[]) {
  const out: { ts: string; allowed: number; throttled: number; locked: number; flagged: number }[] = [];
  for (let i = 0; i < series.length; i += BIN_SECONDS) {
    const chunk = series.slice(i, i + BIN_SECONDS);
    out.push({
      ts: chunk[0].ts,
      // Flagged requests were allowed through; rejected (413) is counted with locked-out traffic.
      allowed: chunk.reduce((n, b) => n + b.allowed + b.flagged, 0),
      flagged: chunk.reduce((n, b) => n + b.flagged, 0),
      throttled: chunk.reduce((n, b) => n + b.throttled, 0),
      locked: chunk.reduce((n, b) => n + b.locked + b.rejected, 0),
    });
  }
  return out;
}

export function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-3 text-[10.5px] text-muted-foreground">
      {SERIES.map((s) => (
        <span key={s.key} className="flex items-center gap-1.5">
          <span className="inline-block size-2.5 rounded-sm" style={{ background: s.color }} aria-hidden />
          {s.label}
        </span>
      ))}
    </div>
  );
}

export function RequestVolumeChart({ series }: { series: MetricsBucket[] }) {
  const data = useMemo(() => bin(series), [series]);
  return (
    <div className="h-[180px] w-full" role="img" aria-label="Requests per 10 seconds by policy decision">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} barCategoryGap={2}>
          <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="2 4" />
          <XAxis dataKey="ts" tickFormatter={fmtTime} tick={axisTick} tickLine={false} axisLine={false} minTickGap={48} />
          <YAxis tick={axisTick} tickLine={false} axisLine={false} width={32} allowDecimals={false} />
          <Tooltip
            contentStyle={tooltipStyle}
            cursor={{ fill: 'hsl(var(--secondary))', opacity: 0.5 }}
            labelFormatter={(ts) => `${fmtTime(String(ts))} · ${BIN_SECONDS}s`}
            formatter={(v, name) => [v, SERIES.find((s) => s.key === name)?.label ?? name]}
          />
          {SERIES.map((s, i) => (
            <Bar
              key={s.key}
              dataKey={s.key}
              stackId="v"
              fill={s.color}
              stroke="hsl(var(--card))"
              strokeWidth={1}
              radius={i === SERIES.length - 1 ? [4, 4, 0, 0] : 0}
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SourceRateChart({
  series,
  limit,
  windowSeconds,
}: {
  series: MetricsBucket[];
  limit: number;
  windowSeconds: number;
}) {
  const max = Math.max(limit * 1.25, ...series.map((b) => b.peakSourceRate));
  return (
    <div className="h-[160px] w-full" role="img" aria-label={`Peak per-source requests in ${windowSeconds}s window vs limit ${limit}`}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={series}>
          <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="2 4" />
          <XAxis dataKey="ts" tickFormatter={fmtTime} tick={axisTick} tickLine={false} axisLine={false} minTickGap={48} />
          <YAxis tick={axisTick} tickLine={false} axisLine={false} width={32} domain={[0, Math.ceil(max)]} allowDecimals={false} />
          <Tooltip
            contentStyle={tooltipStyle}
            labelFormatter={(ts) => fmtTime(String(ts))}
            formatter={(v) => [`${v} req / ${windowSeconds}s`, 'Peak source']}
          />
          <ReferenceLine
            y={limit}
            stroke="var(--chart-throttled)"
            strokeDasharray="4 3"
            label={{ value: `limit ${limit}`, position: 'insideTopRight', fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
          />
          <Line
            type="monotone"
            dataKey="peakSourceRate"
            stroke="hsl(var(--primary))"
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4, stroke: 'hsl(var(--card))', strokeWidth: 2 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

'use client';

import { riskColor } from '@/lib/graph/nodeMeta';

export function RiskGauge({ score, size = 140 }: { score: number; size?: number }) {
  const r = size / 2 - 12;
  const circ = Math.PI * r; // semicircle
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const color = riskColor(score);

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 2 + 20} viewBox={`0 0 ${size} ${size / 2 + 20}`}>
        <path
          d={`M 12 ${size / 2} A ${r} ${r} 0 0 1 ${size - 12} ${size / 2}`}
          fill="none"
          stroke="hsl(var(--border))"
          strokeWidth={10}
          strokeLinecap="round"
        />
        <path
          d={`M 12 ${size / 2} A ${r} ${r} 0 0 1 ${size - 12} ${size / 2}`}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)}
          style={{ transition: 'stroke-dashoffset 600ms ease' }}
        />
        <text
          x={size / 2}
          y={size / 2 - 6}
          textAnchor="middle"
          className="font-mono"
          fill="hsl(var(--foreground))"
          fontSize={28}
          fontWeight={600}
        >
          {Math.round(score)}
        </text>
        <text
          x={size / 2}
          y={size / 2 + 14}
          textAnchor="middle"
          fill="hsl(var(--muted-foreground))"
          fontSize={11}
        >
          risk score
        </text>
      </svg>
    </div>
  );
}
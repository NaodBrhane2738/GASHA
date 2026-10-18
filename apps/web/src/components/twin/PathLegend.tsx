'use client';

export function PathLegend() {
  const items = [
    { c: 'hsl(var(--critical))', l: 'Active attack path' },
    { c: 'hsl(var(--high))', l: 'Exploitable edge' },
    { c: 'hsl(var(--medium))', l: 'Crown jewel' },
    { c: 'hsl(var(--border))', l: 'Normal dependency' },
  ];
  return (
    <div className="pointer-events-auto absolute bottom-4 left-4 z-10 flex items-center gap-4 rounded-lg border border-border bg-card/90 px-3 py-2 text-[11px] text-muted-foreground backdrop-blur">
      {items.map((i) => (
        <div key={i.l} className="flex items-center gap-1.5">
          <span className="inline-block size-2 rounded-sm" style={{ background: i.c }} />
          {i.l}
        </div>
      ))}
    </div>
  );
}
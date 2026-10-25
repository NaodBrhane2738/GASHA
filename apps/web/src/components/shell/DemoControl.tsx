'use client';

import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { ChevronDown, ChevronUp, FlaskConical, Pause, Play, RotateCcw, Zap } from 'lucide-react';
import { cn } from '@/lib/utils';
import { sendCommand, useSim } from '@/lib/sim/runtime';
import { SCENARIOS, type ScenarioId } from '@/lib/sim/engine';

const HIDE_KEY = 'gasha.demoControl.hidden';

/**
 * Presenter controls for the simulation. Shift+D hides/shows the panel for clean recordings.
 */
export function DemoControl() {
  const autopilot = useSim((s) => s.state?.autopilot ?? true);
  const traffic = useSim((s) => s.state?.traffic ?? true);
  const active = useSim((s) => s.state?.activeScenario?.id ?? null);
  const [open, setOpen] = useState(false);
  // Rendered only after the client-side session check, so reading storage here is safe.
  const [hidden, setHidden] = useState(() => {
    try {
      return localStorage.getItem(HIDE_KEY) === '1';
    } catch {
      return false;
    }
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.shiftKey && e.key.toLowerCase() === 'd' && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
        setHidden((h) => {
          try {
            localStorage.setItem(HIDE_KEY, h ? '0' : '1');
          } catch {
            /* ignore */
          }
          return !h;
        });
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  if (hidden) return null;

  const run = (id: ScenarioId, label: string) => {
    sendCommand({ type: 'scenario', id }).then(
      () => toast.message(`Simulating: ${label}`, { description: 'Synthetic traffic against the sandbox store' }),
      () => toast.error('Simulation is starting — try again in a second'),
    );
  };

  return (
    <div className="fixed bottom-4 left-4 z-40 w-[calc(100vw-2rem)] max-w-[300px] rounded-xl border bg-card/95 shadow-2xl backdrop-blur">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left text-[12px] font-semibold"
        aria-expanded={open}
      >
        <FlaskConical className="size-4 text-primary" />
        Demo control
        {active && (
          <span className="ml-1 flex items-center gap-1 rounded bg-[hsl(var(--critical))]/15 px-1.5 py-0.5 text-[10px] font-medium text-[hsl(var(--critical))]">
            <span className="size-1.5 animate-pulse rounded-full bg-[hsl(var(--critical))]" /> attack running
          </span>
        )}
        <span className="ml-auto text-muted-foreground">{open ? <ChevronDown className="size-4" /> : <ChevronUp className="size-4" />}</span>
      </button>

      {open && (
        <div className="space-y-3 border-t px-3 pb-3 pt-2.5">
          <div className="space-y-1.5">
            {SCENARIOS.map((s) => (
              <button
                key={s.id}
                onClick={() => run(s.id, s.label)}
                disabled={!!active}
                className={cn(
                  'flex w-full items-center gap-2 rounded-md border px-2.5 py-1.5 text-left text-[11.5px] transition-colors hover:bg-secondary disabled:opacity-50',
                  active === s.id && 'border-[hsl(var(--critical))]/60',
                )}
              >
                <Zap className="size-3.5 shrink-0 text-[hsl(var(--high))]" />
                <span className="font-medium">{s.label}</span>
                <span className="ml-auto text-[10px] text-muted-foreground">{s.expect}</span>
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Toggle on={autopilot} onClick={() => sendCommand({ type: 'autopilot', on: !autopilot })} label="Autopilot" />
            <Toggle on={traffic} onClick={() => sendCommand({ type: 'traffic', on: !traffic })} label="Live traffic" />
            <button
              onClick={() => sendCommand({ type: 'reset' }).then(() => toast.success('Simulation reset'))}
              className="ml-auto flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] text-muted-foreground hover:bg-secondary"
            >
              <RotateCcw className="size-3" /> Reset
            </button>
          </div>
          <p className="text-[10px] text-muted-foreground">All traffic is synthetic. Shift+D hides this panel.</p>
        </div>
      )}
    </div>
  );
}

function Toggle({ on, onClick, label }: { on: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={on}
      className={cn(
        'flex items-center gap-1 rounded-md border px-2 py-1 text-[11px]',
        on ? 'border-primary/50 bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-secondary',
      )}
    >
      {on ? <Pause className="size-3" /> : <Play className="size-3" />} {label}
    </button>
  );
}

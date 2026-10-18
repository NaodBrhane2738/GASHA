'use client';

import { useState } from 'react';
import { Bot, Send, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { useUI } from '@/store/ui';

const PRESETS = [
  'Summarize incident inc-1',
  'Which path is most likely exploitable?',
  'What would isolating auth-svc cost us?',
];

export function AnalystDock() {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState('');
  const selectedIncident = useUI((s) => s.selectedIncidentId);

  return (
    <>
      <Button
        onClick={() => setOpen(true)}
        className="fixed bottom-5 right-5 z-40 h-11 gap-2 rounded-full shadow-lg"
      >
        <Bot className="size-4" /> AI Analyst
      </Button>

      {open && (
        <div className="fixed bottom-5 right-5 z-50 w-[380px] rounded-lg border border-border bg-card shadow-2xl">
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <div className="flex items-center gap-2 text-[12.5px] font-medium">
              <Bot className="size-4 text-primary" /> AI Analyst
              {selectedIncident && (
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  ctx: {selectedIncident}
                </span>
              )}
            </div>
            <Button variant="ghost" size="icon" className="size-7" onClick={() => setOpen(false)}>
              <X className="size-3.5" />
            </Button>
          </div>

          <div className="max-h-[260px] space-y-2 overflow-y-auto px-3 py-3 text-[12.5px]">
            <div className="rounded-md bg-secondary p-2 text-muted-foreground">
              Ask about the current incident, path, or blast radius. Answers cite detections and
              twin nodes.
            </div>
          </div>

          <div className="flex flex-wrap gap-1 border-t border-border px-3 py-2">
            {PRESETS.map((p) => (
              <button
                key={p}
                onClick={() => setValue(p)}
                className="rounded-full border border-border px-2 py-0.5 text-[10.5px] text-muted-foreground hover:text-foreground"
              >
                {p}
              </button>
            ))}
          </div>

          <div className="flex items-end gap-2 border-t border-border p-3">
            <Textarea
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="Ask the analyst…"
              className="min-h-[42px] resize-none text-[12.5px]"
            />
            <Button size="icon" className="size-9 shrink-0" disabled={!value.trim()}>
              <Send className="size-3.5" />
            </Button>
          </div>
        </div>
      )}
    </>
  );
}
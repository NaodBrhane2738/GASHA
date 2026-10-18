import { LoopRail } from '@/components/loop/LoopRail';
import { AnalystDock } from '@/components/analyst/AnalystDock';

export default function ShellLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="flex items-center justify-between border-b border-border px-4 py-2.5">
        <div className="flex items-center gap-2.5">
          <div className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary">
            <span className="text-[13px] font-bold">G</span>
          </div>
          <div>
            <div className="text-[13px] font-semibold leading-none">Gasha AEGIS</div>
            <div className="text-[10.5px] text-muted-foreground">Security Operations</div>
          </div>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <span className="inline-block size-2 rounded-full bg-[hsl(var(--low))]" />
          Connected · demo environment
        </div>
      </header>

      <LoopRail />

      <main className="flex-1 overflow-hidden">{children}</main>

      <AnalystDock />
    </div>
  );
}
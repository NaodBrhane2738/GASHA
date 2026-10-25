import { LoopRail } from '@/components/loop/LoopRail';
import { PolicyBanner } from '@/components/soc/PolicyBanner';
import { AuthGate, ShellHeader } from '@/components/shell/ShellChrome';
import { DemoControl } from '@/components/shell/DemoControl';

export default function ShellLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGate>
      <div className="flex min-h-screen flex-col bg-background">
        <ShellHeader />
        <PolicyBanner />
        <LoopRail />
        <main className="flex-1 overflow-hidden">{children}</main>
        <DemoControl />
      </div>
    </AuthGate>
  );
}

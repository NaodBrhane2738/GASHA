'use client';

import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Lock, Search, ShieldCheck, ShoppingCart, Timer, User, X } from 'lucide-react';
import { sendCommand, useSim, type StoreResult } from '@/lib/sim/runtime';
import { VISITOR_IP } from '@/lib/sim/engine';
import { PRODUCTS, type Product } from '@/lib/sim/seed';
import { fmtRemaining } from '@/components/soc/meta';

const DEMO_INPUTS = [
  { label: 'Normal search', value: 'headphones' },
  { label: 'SQL injection', value: "' OR '1'='1' --" },
  { label: 'XSS probe', value: '<script>alert(1)</script>' },
];

export default function StorePage() {
  const lock = useSim((s) => s.state?.mitigations.find((m) => m.sourceKey === VISITOR_IP) ?? null);
  const incidentId = useSim((s) => s.state?.incidents.find((i) => i.sourceKey === VISITOR_IP && i.status !== 'RESOLVED')?.id);
  const [now, setNow] = useState(() => Date.now());
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<Product[] | null>(null);
  const [notice, setNotice] = useState<{ tone: 'warn' | 'info'; text: string } | null>(null);
  const [cart, setCart] = useState(0);
  const [loginOpen, setLoginOpen] = useState(false);
  const [user, setUser] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const lockedUntil = lock ? new Date(lock.expiresAt).getTime() : 0;
  const isLocked = lock?.action === 'LOCK' && lockedUntil > now;
  const isThrottled = lock?.action === 'THROTTLE' && lockedUntil > now;

  const handle = (r: StoreResult) => {
    if (r.status === 423 || r.status === 429) return false;
    if (r.action === 'FLAG') setNotice({ tone: 'warn', text: 'Your input contained markup and was neutralised by GASHA. This request was logged for review.' });
    return true;
  };

  const run = async (kind: 'search' | 'login' | 'product' | 'cart', args: Record<string, string>) => {
    setBusy(true);
    try {
      return await sendCommand<StoreResult>({ type: 'store', kind, args });
    } catch {
      toast.error('Store is starting up — try again');
      return null;
    } finally {
      setBusy(false);
    }
  };

  const search = async (e?: React.FormEvent, q = query) => {
    e?.preventDefault();
    setNotice(null);
    const r = await run('search', { q });
    if (!r || !handle(r)) return;
    setResults(r.products ?? []);
  };

  const shown = useMemo(() => results ?? PRODUCTS, [results]);

  return (
    <div className="min-h-screen bg-[#f6f7fb] text-[#141824]">
      <div className="flex items-center justify-center gap-2 bg-[#0f172a] px-3 py-1.5 text-center text-[11px] text-slate-200">
        <ShieldCheck className="size-3.5 text-emerald-400" />
        Protected by <strong>GASHA</strong> — real-time rule-based threat defence · sandbox demo store (all traffic simulated)
      </div>

      <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/95 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="flex size-8 items-center justify-center rounded-lg bg-indigo-600 text-[13px] font-bold text-white">G</div>
            <div className="leading-tight">
              <div className="text-[15px] font-bold">GASHA</div>
              <div className="text-[9px] uppercase tracking-[0.2em] text-slate-500">Market</div>
            </div>
          </div>
          <form onSubmit={search} className="order-3 flex w-full items-center gap-2 sm:order-none sm:ml-4 sm:w-auto sm:flex-1">
            <div className="flex flex-1 items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-2 focus-within:ring-2 focus-within:ring-indigo-500">
              <Search className="size-4 text-slate-400" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search products…"
                aria-label="Search products"
                className="w-full bg-transparent text-[14px] outline-none placeholder:text-slate-400"
              />
            </div>
            <button disabled={busy} className="rounded-lg bg-slate-900 px-4 py-2 text-[13px] font-medium text-white hover:bg-slate-800 disabled:opacity-60">
              Search
            </button>
          </form>
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => (user ? setUser(null) : setLoginOpen(true))}
              className="flex items-center gap-1.5 rounded-lg border border-slate-300 px-3 py-2 text-[13px] hover:bg-slate-50"
            >
              <User className="size-4" /> {user ? 'Sign out' : 'Sign in'}
            </button>
            <div className="flex items-center gap-1.5 rounded-lg bg-indigo-50 px-3 py-2 text-[13px] text-indigo-700">
              <ShoppingCart className="size-4" /> {cart}
            </div>
          </div>
        </div>
      </header>

      {isThrottled && (
        <div role="alert" className="flex items-center justify-center gap-2 bg-amber-100 px-4 py-2 text-[13px] text-amber-900">
          <Timer className="size-4" /> HTTP 429 · Too many requests — please slow down. Retry in {fmtRemaining(lockedUntil - now)}.
        </div>
      )}

      <main className="mx-auto max-w-6xl px-4 py-8">
        {results === null ? (
          <section className="mb-10 grid items-center gap-8 md:grid-cols-[1.2fr_1fr]">
            <div>
              <h1 className="text-[30px] font-extrabold leading-tight sm:text-[38px]">
                Everything you need.
                <br />
                Protected end-to-end.
              </h1>
              <p className="mt-3 max-w-md text-[14px] text-slate-600">
                Shop a storefront defended in real time by GASHA — rule-based threat detection, automatic rate limiting and
                instant lockout of hostile sources.
              </p>
              <div className="mt-5 flex flex-wrap gap-2">
                <a href="#products" className="rounded-lg bg-indigo-600 px-4 py-2 text-[13px] font-medium text-white hover:bg-indigo-700">Shop now</a>
                <button onClick={() => setLoginOpen(true)} className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-[13px] font-medium hover:bg-slate-50">
                  Customer sign in
                </button>
              </div>
            </div>
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Live protection</div>
              {[
                ['Injection & traversal signatures', 'Hostile input is blocked and the source locked (HTTP 423)'],
                ['Adaptive rate limiting', 'Bursts are throttled (HTTP 429), persistent abuse escalates'],
                ['Instant response', 'Analysts alerted by email; containment one click away'],
              ].map(([t, d]) => (
                <div key={t} className="flex gap-3 border-t border-slate-100 py-3 first:border-0">
                  <ShieldCheck className="mt-0.5 size-4 shrink-0 text-emerald-600" />
                  <div>
                    <div className="text-[13px] font-semibold">{t}</div>
                    <div className="text-[12px] text-slate-500">{d}</div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        ) : (
          <div className="mb-4 flex flex-wrap items-center gap-2 text-[13px]">
            <span className="text-slate-600">
              {shown.length} result{shown.length === 1 ? '' : 's'} for <span className="font-mono">“{query}”</span>
            </span>
            <button onClick={() => { setResults(null); setQuery(''); setNotice(null); }} className="text-indigo-600 hover:underline">
              Clear search
            </button>
          </div>
        )}

        {notice && (
          <div role="status" className="mb-4 rounded-lg border border-amber-300 bg-amber-50 px-4 py-2.5 text-[13px] text-amber-900">
            {notice.text}
          </div>
        )}

        <section id="products">
          <h2 className="mb-3 text-[16px] font-bold">{results === null ? 'Featured products' : 'Results'}</h2>
          {shown.length === 0 ? (
            <div className="rounded-xl border border-dashed border-slate-300 bg-white px-4 py-10 text-center text-[13px] text-slate-500">
              No products match your search.
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              {shown.map((p) => (
                <article key={p.id} className="group overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm transition hover:shadow-md">
                  <button onClick={() => run('product', { id: p.id })} className="block w-full text-left">
                    <div
                      className="flex aspect-[4/3] items-center justify-center"
                      style={{ background: `linear-gradient(135deg, hsl(${p.hue} 70% 85%), hsl(${p.hue + 30} 60% 65%))` }}
                    >
                      <div className="size-14 rounded-2xl bg-white/50 shadow-inner transition group-hover:scale-105" />
                    </div>
                  </button>
                  <div className="p-3">
                    <div className="mb-1 inline-block rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700">{p.tag}</div>
                    <div className="line-clamp-2 min-h-[36px] text-[13px] font-medium">{p.name}</div>
                    <div className="mt-2 flex items-center justify-between">
                      <span className="text-[15px] font-bold">${p.price}</span>
                      <button
                        onClick={async () => {
                          const r = await run('cart', { id: p.id });
                          if (r && handle(r)) {
                            setCart((c) => c + 1);
                            toast.success(`Added ${p.name}`);
                          }
                        }}
                        className="rounded-md bg-slate-900 px-2.5 py-1 text-[12px] text-white hover:bg-slate-800"
                      >
                        Add
                      </button>
                    </div>
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>

        <section className="mt-10 rounded-xl border border-slate-200 bg-white p-4">
          <div className="mb-2 text-[12px] font-semibold text-slate-700">Presenter shortcuts — fill the search box</div>
          <div className="flex flex-wrap gap-2">
            {DEMO_INPUTS.map((d) => (
              <button
                key={d.label}
                onClick={() => setQuery(d.value)}
                className="rounded-md border border-slate-300 px-2.5 py-1 text-[12px] hover:bg-slate-50"
              >
                {d.label}: <span className="font-mono">{d.value}</span>
              </button>
            ))}
          </div>
          <p className="mt-2 text-[11px] text-slate-500">
            Customer login for the demo: <span className="font-mono">shopper@gasha.market</span> / <span className="font-mono">shop123</span>. Five wrong
            passwords in a minute trigger a lockout.
          </p>
        </section>
      </main>

      {loginOpen && !isLocked && (
        <LoginDialog
          onClose={() => setLoginOpen(false)}
          onSubmit={async (email, password) => {
            const r = await run('login', { email, password });
            if (!r || !handle(r)) return 'blocked';
            if (r.status === 401) return 'invalid';
            setUser(email);
            setLoginOpen(false);
            toast.success('Signed in');
            return 'ok';
          }}
        />
      )}

      {isLocked && (
        <div role="alertdialog" aria-modal="true" aria-labelledby="locked-title" className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-2xl bg-white p-6 text-center shadow-2xl">
            <div className="mx-auto mb-3 flex size-12 items-center justify-center rounded-full bg-red-100">
              <Lock className="size-6 text-red-600" />
            </div>
            <div className="font-mono text-[12px] font-semibold text-red-600">HTTP 423 · Locked</div>
            <h2 id="locked-title" className="mt-1 text-[20px] font-bold">Access temporarily locked</h2>
            <p className="mt-2 text-[13px] text-slate-600">
              GASHA detected hostile activity from your connection and locked it by policy <span className="font-mono">{lock?.ruleId}</span>.
            </p>
            <div className="mt-4 grid grid-cols-2 gap-2 text-left text-[12px]">
              <div className="rounded-lg bg-slate-50 p-2.5">
                <div className="text-slate-500">Retry in</div>
                <div className="font-mono text-[15px] font-semibold">{fmtRemaining(lockedUntil - now)}</div>
              </div>
              <div className="rounded-lg bg-slate-50 p-2.5">
                <div className="text-slate-500">Reference</div>
                <div className="truncate font-mono text-[13px] font-semibold">{incidentId ?? '—'}</div>
              </div>
            </div>
            <p className="mt-4 text-[11px] text-slate-500">An analyst has been alerted. This lock lifts automatically or when released from the SOC console.</p>
          </div>
        </div>
      )}
    </div>
  );
}

function LoginDialog({ onClose, onSubmit }: { onClose: () => void; onSubmit: (email: string, password: string) => Promise<'ok' | 'invalid' | 'blocked'> }) {
  const [email, setEmail] = useState('shopper@gasha.market');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  return (
    <div role="dialog" aria-modal="true" aria-labelledby="login-title" className="fixed inset-0 z-40 flex items-center justify-center bg-slate-950/50 p-4">
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          const r = await onSubmit(email, password);
          setBusy(false);
          if (r === 'invalid') setError('Incorrect email or password.');
          if (r === 'blocked') setError('Too many attempts. Please wait before trying again.');
        }}
        className="w-full max-w-sm rounded-2xl bg-white p-6 shadow-2xl"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 id="login-title" className="text-[17px] font-bold">Sign in to GASHA Market</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 hover:bg-slate-100">
            <X className="size-4" />
          </button>
        </div>
        <label className="mb-1 block text-[12px] font-medium" htmlFor="store-email">Email</label>
        <input id="store-email" value={email} onChange={(e) => setEmail(e.target.value)} className="mb-3 w-full rounded-lg border border-slate-300 px-3 py-2 text-[14px] outline-none focus:ring-2 focus:ring-indigo-500" />
        <label className="mb-1 block text-[12px] font-medium" htmlFor="store-password">Password</label>
        <input id="store-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="mb-3 w-full rounded-lg border border-slate-300 px-3 py-2 text-[14px] outline-none focus:ring-2 focus:ring-indigo-500" />
        {error && <p role="alert" className="mb-3 text-[12px] text-red-600">{error}</p>}
        <button disabled={busy} className="w-full rounded-lg bg-indigo-600 py-2 text-[14px] font-medium text-white hover:bg-indigo-700 disabled:opacity-60">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}

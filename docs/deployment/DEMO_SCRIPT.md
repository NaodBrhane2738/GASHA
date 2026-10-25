# Recording the GASHA demo

The dashboard runs a deterministic simulation entirely in the browser: a sandbox store
(GASHA Market) receives synthetic traffic and attacks, and every console page shows the same
incidents, responses and risk at the same moment. No backend, no external requests.

## Setup (2 minutes before recording)

1. Open the deployed site (or `npm run dev` in `apps/web`) and sign in with **admin / admin123**
   (pre-filled).
2. Open **Demo store** (header button) — it opens in a new window. Put the store and the SOC
   side by side; they stay in sync live.
3. In **Demo control** (bottom-left, click to expand) switch **Autopilot off** so attacks only
   happen when you trigger them. Press **Reset** for a fresh, consistent starting state.
4. `Shift + D` hides the Demo control panel when you want a clean frame.

## Suggested flow (~4 minutes)

| Step | Where | What to do / say |
| --- | --- | --- |
| 1 | `/soc` | Live traffic, request log, latency. "Every request is classified by deterministic rules." |
| 2 | Store window | Search `headphones` — normal results. |
| 3 | Store window | Click the **SQL injection** shortcut, then Search → full-screen **HTTP 423 Locked** with an incident reference. |
| 4 | SOC window | Red 423 banner, new CRITICAL incident walking Ingestion → Detection → Enforcement → Mitigation, alert email toast, finding + root cause + hardening recommendations. |
| 5 | `/incidents/<id>` | **Replay attack** steps through the story on the digital twin. |
| 6 | `/response` | Approve the proposed containment (type CONFIRM) → path turns *mitigated*, risk drops on `/risk`. |
| 7 | SOC | **Release** the store visitor's lock → the store window unlocks instantly. |
| 8 | Demo control | Run **Scraper burst** → HTTP 429 throttling that escalates to a 423 lock; watch the rate-vs-limit chart. |
| 9 | Demo control | **Credential stuffing** / **Path traversal** / **XSS probe** for the other rule types. |

Store customer login for the brute-force demo: `shopper@gasha.market` / `shop123` (five wrong
passwords within a minute lock the visitor).

## Good to know

- Locks last 5 minutes; throttles last until the rate drops. The banner shows the countdown.
- State survives a page reload for up to 10 minutes (Reset clears it).
- Close extra copies of the site before recording; the visible window drives the simulation.
- The monitored deployment shown in the header (`gasha-cve-sentinel.vercel.app`) is a label;
  its status is simulated and no traffic is sent to it.

# GASHA local demo runbook

GASHA runs on one laptop. Only the client website (the protected demo app) is hosted.

```
 Client website (hosted, own Supabase)
     |  telemetry  ->  ngrok tunnel  ->  laptop :4000  (GASHA backend)
     |  <- response actions (block IP, disable session) from the backend
 Laptop:  backend :4000   dashboard :3000   local SQLite (optional)
 Internet: GitHub + Vercel APIs  <-  GASHA connectors (read-only tokens)
```

## One-time setup (each laptop that will run the demo)

1. **Python 3.13 environment**: `py -3.13 -m venv .venv`, then `.\.venv\Scripts\Activate.ps1`, then `pip install -r apps\api\requirements-dev.txt`. The prompt must start with `(.venv)`.
2. **Dashboard**: `pnpm install`, then `pnpm --filter @gasha/web build` (run again after code changes).
3. **Windows Security exclusion** for the repo folder (Virus & threat protection -> Manage settings -> Exclusions). It stops slow builds and broken packages.
4. **ngrok** (free account): install it, run `ngrok config add-authtoken <your token>` (the token is private), and note the dev domain shown in the ngrok dashboard.
5. **Local `.env`** (never committed). Add what you have:
   `GASHA_TELEMETRY_API_KEY`, `GITHUB_TOKEN`, `VERCEL_API_TOKEN`, `GASHA_PUBLIC_URL` (your ngrok address), `CLIENT_SITE_URL`, `NEXT_PUBLIC_API_USER`, `NEXT_PUBLIC_API_PASSWORD`.
6. Give the client website's owner the telemetry URL (`<ngrok address>/api/v1/telemetry/ingest`) and the same `GASHA_TELEMETRY_API_KEY`, privately (not in a group chat).



Then, in this order:

1. Terminal 1: `python scripts/demo/run_demo.py --persist` (backend + dashboard; `--persist` keeps incidents in a local file).
2. Terminal 2: `ngrok http 4000`. The "Forwarding" address must match the dev domain in your ngrok dashboard (if it does not, use `ngrok http --url=<dev-domain> 4000`).
3. Terminal 3: `python scripts/demo/preflight.py`. Do not start until it says READY.
4. Run the demo flow.
5. When finished: Ctrl+C in all terminals (this also closes the public tunnel).

## Reset between runs

Ctrl+C the launcher, then `python scripts/demo/reset_local.py` (moves the local database to a backup folder; nothing is deleted), then start again.

## If something breaks

| Symptom | Likely cause | Fix |
|---|---|---|
| Preflight: Python version | `.venv` is not 3.13 | Recreate: `py -3.13 -m venv .venv`, reinstall |
| Launcher: port already in use | An old backend or dashboard is running | Close the old terminal, or end the process |
| Preflight: Backend not reachable | Backend crashed | Read the `[api]` lines in terminal 1, restart the launcher |
| Preflight: Tunnel FAIL | ngrok not running, wrong port, or wrong `GASHA_PUBLIC_URL` | Restart `ngrok http 4000`, compare the address |
| Preflight: GitHub or Vercel token FAIL | Expired or revoked token | Create a new one (Vercel needs personal-account scope), update `.env` |
| Preflight: Client website FAIL | Deployment down | Check the Vercel dashboard for the client site |
| Dashboard slow or blank | Running `--dev`, or data mode empty | Use the production build; check the data mode with the backend owners |
| Backend crashed mid-demo | n/a | Start the launcher again with `--persist`: incidents are kept |

## Security notes

- While ngrok runs, the backend is reachable from the internet. Run the tunnel only for rehearsals and the demo.
- Never commit `.env` or the ngrok token. Rotate all tokens after the competition.
- The telemetry key must match on both sides, and must not be in Git.
- The local database lives in `apps/data/`. Add `apps/data/` to `.gitignore` so its `-wal` and `-shm` files are never committed.
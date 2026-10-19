# GASHA environment variables

One place that says what every setting is, who reads it, whether it is secret, and what it must be in each environment.
Source of truth for the names: `.env.example`, `apps/api/app/core/config.py`, `apps/web/src`, `apps/demo-target`.

**Rules**
- Real values live only in your local `.env` (git-ignored) or in the hosting provider's environment settings. Never in Git, chat, screenshots or the frontend.
- Anything starting with `NEXT_PUBLIC_` is bundled into the browser. Treat it as public.
- Secrets differ per environment (local / demo-prod). Generate them with `python scripts/dev/generate_secrets.py`.
- `local` = your machine. `deployed` = the hosted demo.

## Backend (`apps/api`)

| Variable | What it does | Local value | Secret | Deployed |
|---|---|---|---|---|
| `NODE_ENV` | Environment name (`development` / `production`) | `development` | no | `production` |
| `API_PORT`, `API_HOST` | Port and bind address | `4000`, `0.0.0.0` | no | The host's `PORT` (see Docker note) |
| `API_BASE_URL` | Public URL of the API, including `/api/v1` | `http://localhost:4000/api/v1` | no | Your deployed API URL |
| `WEB_URL` | Public URL of the frontend | `http://localhost:3000` | no | Your Vercel URL |
| `LOG_LEVEL` | Log verbosity | `debug` | no | `info` |
| `CORS_ORIGINS` | Browser origins allowed to call the API. **Must be a JSON list** | `["http://localhost:3000","http://localhost:3001"]` | no | `["https://<your-app>.vercel.app"]` |
| `GASHA_STORAGE_BACKEND` | `memory` (default) or `sql`. Incidents, detections, responses and the audit trail only persist with `sql` | `memory` | no | `sql` |
| `GASHA_DB_DIALECT` | `sqlite` (default) or `postgres` (Supabase) | `sqlite` | no | `postgres` |
| `GASHA_DATABASE_PATH` | SQLite file path (only when dialect is sqlite) | `<repo>/apps/data/gasha_storage.db` | no | not used |
| `GASHA_DB_POOL_MAX` | Max Postgres connections held by the API | `5` | no | `5` |
| `DATABASE_URL` | Postgres connection. **Use Supabase's Session pooler URI (port 5432)**, not the direct host | placeholder | **yes** (has the DB password) | Supabase pooler URI |
| `DIRECT_URL` | Defined in settings, not read by any code today | empty | yes | leave empty |
| `SUPABASE_URL` | Project URL | `https://<ref>.supabase.co` | no | same |
| `SUPABASE_ANON_KEY` | Public (publishable) key | from dashboard | no, but keep out of Git | same |
| `SUPABASE_SERVICE_ROLE_KEY` | Secret key. Bypasses row-level security | from dashboard | **yes** | secret setting |
| `REDIS_URL` | Redis address. Not used by the current code | `redis://localhost:6379` | no | leave default |
| `JWT_SECRET` | Signs login tokens. Minimum 32 characters | dev placeholder is fine | **yes** | unique strong value |
| `JWT_EXPIRES_IN` | Login token lifetime | `24h` | no | `24h` |
| `INTERNAL_API_KEY` | Service-to-service key | dev placeholder | **yes** | unique strong value |
| `CREDENTIAL_ENCRYPTION_KEY` | Encrypts stored GitHub/Vercel tokens. Changing it makes stored tokens unreadable. Required outside development | empty (generate one) | **yes** | unique value, kept safe |
| `GASHA_PROVISIONING_TOKEN` | First-administrator bootstrap token (min 32 chars), checked by `production_guard.py` | not needed | **yes** | unique strong value if the guard is enabled |
| `VERCEL_API_TOKEN`, `VERCEL_TEAM_ID`, `VERCEL_PROJECT_ID` | Vercel read access. The connect endpoint takes the token in its request, so these are optional defaults | empty | token: **yes** | optional |
| `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | For a future GitHub App / OAuth. **Not used by the token-based MVP** | empty | secret/key: **yes** | leave empty |
| `VERCEL_WEBHOOK_SECRET`, `GITHUB_WEBHOOK_SECRET` | For future webhooks. Not used by the MVP | empty | **yes** | leave empty |
| `GASHA_TELEMETRY_API_KEY` | Key the demo app must send when posting telemetry | dev placeholder | **yes** | unique strong value, same on both sides |
| `GASHA_TELEMETRY_ENVIRONMENT` | Environment id telemetry is filed under | `env-prod` | no | `env-prod` |
| `GASHA_TELEMETRY_MAX_BATCH_SIZE`, `GASHA_TELEMETRY_MAX_PAYLOAD_BYTES`, `GASHA_TELEMETRY_BUFFER_CAPACITY` | Telemetry limits | `100`, `1048576`, `5000` | no | defaults |
| `GASHA_TELEMETRY_TRUSTED_PROXIES` | Proxy addresses whose forwarded IP is trusted | `127.0.0.1`, `::1` | no | add the host's proxy range if source IPs look wrong |

## Frontend (`apps/web`)

| Variable | What it does | Local value | Secret | Deployed |
|---|---|---|---|---|
| `NEXT_PUBLIC_API_URL` | API base URL the browser calls | `http://127.0.0.1:4000/api/v1` | **public** | `https://<api-host>/api/v1` |
| `BACKEND_URL` | Target of the `/api/v1/*` rewrite in `next.config.ts` | `http://127.0.0.1:4000` | no | `https://<api-host>` |
| `NEXT_PUBLIC_USE_MOCK` | `true` starts the mock server instead of the real API | unset | no | unset |
| `NEXT_PUBLIC_API_USER`, `NEXT_PUBLIC_API_PASSWORD`, `NEXT_PUBLIC_API_ENV` | Demo login the app uses automatically | built-in demo defaults | **public** (in the browser bundle) | a low-privilege demo account only |
| `DEEPSEEK_API_KEY`, `NEXT_PUBLIC_DEEPSEEK_API_KEY`, `DEEPSEEK_API_BASE_URL` | Leftover AI config in `src/lib/config.ts`. The backend uses no AI keys | unset | **never set** | unset |

## Demo target (`apps/demo-target`)

| Variable | What it does | Local value | Secret | Deployed |
|---|---|---|---|---|
| `GASHA_TELEMETRY_ENDPOINT` | Where it sends telemetry | `http://localhost:4000/api/v1/telemetry/ingest` | no | `https://<api-host>/api/v1/telemetry/ingest` |
| `GASHA_TELEMETRY_API_KEY` | Must equal the backend's key | dev placeholder | **yes** | same value as the backend |
| `GASHA_TELEMETRY_ENVIRONMENT` | Environment id | `env-prod` | no | `env-prod` |

`DEMO_TARGET_PORT`, `DEMO_TARGET_URL`, `DEMO_TARGET_DB_URL`, `DEMO_TARGET_SECRET` appear in `.env.example` but no code reads them yet.

## Tooling

| Variable | Used by | Notes |
|---|---|---|
| `DATABASE_URL` | `infra/scripts/apply_migrations.py` | Session pooler URI. Never printed by the script |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | `scripts/dev/check_supabase.py` | Never printed |
| `GASHA_TEST_DATABASE_URL` | `tests/integration/test_postgres_engine.py` | Scratch database only. The tests delete rows |

## Known gaps in `.env.example` (to fix)

1. `MAX_BATCH_SIZE`, `MAX_PAYLOAD_BYTES`, `BUFFER_CAPACITY`, `GASHA_TELEMETRY_FLUSH_INTERVAL_MS`, `GASHA_TELEMETRY_BATCH_SIZE` do not match the names the backend reads (`GASHA_TELEMETRY_MAX_BATCH_SIZE`, etc.), so setting them has no effect.
2. `GASHA_STORAGE_BACKEND`, `GASHA_DB_DIALECT` and `GASHA_PROVISIONING_TOKEN` are read by the code but not listed.
3. `DATABASE_URL` in the example uses Supabase's direct host, which is IPv6-only on the free plan. Use the Session pooler URI.
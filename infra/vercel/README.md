# Vercel — operator checklist (DevOps)

Covers (1) Vercel as a **monitored** cloud connection and (2) optional hosting of
the GASHA web app.

## 1. Monitored Vercel account (MVP)

1. Create a least-privilege Vercel API token.
2. Connect via `POST /api/v1/connections/vercel` with `{ "apiToken": "…" }`
   (optional `teamId` / `projectId`).
3. Verify `GET /api/v1/connections/status`.

Details: `docs/integrations/vercel.md`.

Env placeholders: `VERCEL_API_TOKEN`, `VERCEL_TEAM_ID`, `VERCEL_PROJECT_ID`,
`VERCEL_WEBHOOK_SECRET` (webhook unused until Backend adds a receiver).

## 2. Hosting `apps/web` on Vercel (optional)

No `vercel.json` is checked in. If the team deploys the dashboard to Vercel:

| Setting | Typical value |
|---------|----------------|
| Root directory | `apps/web` |
| Install | `pnpm install` (from monorepo; configure as needed) |
| Build | `pnpm --filter @gasha/web build` or `next build` in `apps/web` |
| `NEXT_PUBLIC_API_URL` | `https://<api-host>/api/v1` |
| `BACKEND_URL` | `https://<api-host>` |
| API `CORS_ORIGINS` | include the Vercel origin JSON list |

API hosting blueprint remains root [`render.yaml`](../../render.yaml) (not Vercel).

## 3. Not claimed live

Presence of this README does **not** mean a Vercel project is linked or deployed.

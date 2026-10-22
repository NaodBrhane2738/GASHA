# Vercel Integration Guide

> **ROLE / OWNERSHIP**: DevOps & Backend Engineers  
> **OBJECTIVE**: Configure how GASHA connects to Vercel for discovery (MVP) and document future webhook work.

---

## 1. What the product supports today (MVP)

Runtime integration is **API-token-based**.

| Item | Location |
|------|----------|
| Connect API | `POST /api/v1/connections/vercel` — `apps/api/app/api/connections.py` |
| Request body | `VercelConnectRequest` (`apiToken`, optional `teamId`, `projectId`, `environmentId`) |
| Client | `apps/api/app/integrations/vercel/client.py` |
| Storage | Token encrypted at rest (`CREDENTIAL_ENCRYPTION_KEY`) |

**DevOps configuration checklist**

1. Create a Vercel token with the minimum scopes needed for project/deployment read for the demo account.
2. Submit via the connect API / UI — never commit the token.
3. Optional `.env` defaults: `VERCEL_API_TOKEN`, `VERCEL_TEAM_ID`, `VERCEL_PROJECT_ID` (connect body can supply these instead).
4. `VERCEL_WEBHOOK_SECRET` is reserved; **no Vercel webhook handler exists under `apps/api` today**.

## 2. Resources discovered (implementation intent)

- Projects (`GET /v9/projects` via client)
- Deployments (`GET /v6/deployments`)
- Build/output metadata used by discovery normalizers

## 3. OAuth / webhooks (future)

README mentions OAuth and webhook specifications. The **implemented** path is Bearer token validation in `VercelAPIClient`. OAuth install URLs and webhook receivers are **not** present in the API codebase.

Do not fabricate webhook routes or OAuth client apps in this repo until Backend defines contracts.

## 4. Hosting the GASHA dashboard on Vercel

Separate from “Vercel as a monitored cloud”:

- API deploy blueprint: root `render.yaml` (Docker API → Supabase).
- Web dashboard: no `vercel.json` checked in yet; if the team hosts `apps/web` on Vercel, set `NEXT_PUBLIC_API_URL` / `BACKEND_URL` / `CORS_ORIGINS` per `docs/environment-variables.md`.
- Operator notes: `infra/vercel/README.md`.

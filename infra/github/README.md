# GitHub integration — operator checklist (DevOps)

This folder holds **configuration notes** for GitHub as a GASHA data source.
Application connect logic lives in `apps/api` (Backend-owned code paths).

## MVP (what works in code today)

1. Create a least-privilege GitHub PAT (or installation token) for demo repos.
2. Store it only in the operator’s secret store / local `.env` (never Git).
3. Connect via `POST /api/v1/connections/github` with `{ "token": "…" }` (auth required).
4. Confirm `GET /api/v1/connections/status` shows `GITHUB` connected (no token in response).

Details: `docs/integrations/github.md`.

## Not in this repository yet

- GitHub App manifest / private key files
- OAuth callback URLs
- Webhook receiver + `GITHUB_WEBHOOK_SECRET` verification

Those require Backend API work before DevOps can wire production App settings.

## Related env keys (see `.env.example`)

`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_PATH`, `GITHUB_CLIENT_ID`,
`GITHUB_CLIENT_SECRET`, `GITHUB_WEBHOOK_SECRET`, optional demo `GITHUB_TOKEN`.

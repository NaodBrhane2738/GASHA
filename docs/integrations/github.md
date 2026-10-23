# GitHub Integration Guide

> **ROLE / OWNERSHIP**: DevOps & Backend Engineers  
> **OBJECTIVE**: Configure how GASHA connects to GitHub for discovery (MVP) and document future OAuth/webhook work.

---

## 1. What the product supports today (MVP)

Runtime integration is **token-based**, not a completed GitHub App OAuth install flow.

| Item | Location |
|------|----------|
| Connect API | `POST /api/v1/connections/github` — `apps/api/app/api/connections.py` |
| Request body | `GitHubConnectRequest` in `apps/api/app/schemas/connection.py` (`token` and/or `installationId`, optional `repository` / `repositories`, `environmentId`) |
| Client | `apps/api/app/integrations/github/client.py` |
| Storage | Token encrypted at rest via `CREDENTIAL_ENCRYPTION_KEY` (`apps/api/app/core/crypto.py`) |
| Status / disconnect | `GET /api/v1/connections/status`, disconnect routes in the same module |

**DevOps configuration checklist**

1. Operators obtain a GitHub **fine-scoped PAT** (or installation token) with read access to the repos under demo — least privilege.
2. Token is submitted through the authenticated connect API (or UI), **not** committed to Git.
3. Optional env defaults in `.env.example`: `GITHUB_APP_*`, `GITHUB_CLIENT_*`, `GITHUB_WEBHOOK_SECRET` — reserved for future App/OAuth; **not required for MVP**.
4. Demo preflight may also read `GITHUB_TOKEN` for a connectivity smoke check (`scripts/demo/preflight.py`) — separate from the encrypted connection store.

## 2. Resources discovered (implementation intent)

- Repositories: metadata used by discovery / digital twin pipelines
- Dependency manifests (`package.json`, `requirements.txt`, lockfiles) where the discovery path reads them
- Dependabot / advisory data when the client exposes it

Exact field mapping lives in backend discovery/normalizer modules under `apps/api/app/`.

## 3. OAuth / GitHub App (not implemented as a hosted App flow)

README’s `docs/integrations/` charter mentions OAuth setup. **Current code path validates a bearer/PAT-style token** via `GitHubAPIClient.validate_credentials()`.

Env placeholders for a future App:

| Variable | Purpose | MVP status |
|----------|---------|------------|
| `GITHUB_APP_ID` | GitHub App id | Unused by MVP connect |
| `GITHUB_APP_PRIVATE_KEY_PATH` | PEM path for App JWT | Unused by MVP connect |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | OAuth App | Unused by MVP connect |
| `GITHUB_WEBHOOK_SECRET` | Webhook HMAC | **No webhook routes in `apps/api` today** |

**Do not invent webhook endpoints or OAuth redirect URLs in infra until Backend adds them.**

## 4. Infra folder

See `infra/github/README.md` for operator-facing checklist (secrets location, Render/env wiring). No live GitHub App manifest is checked into this repo.

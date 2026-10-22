# `infra/` — DevOps ownership

| Path | Purpose |
|------|---------|
| `docker/docker-compose.yml` | Local multi-container stack (web, api, postgres, redis) |
| `database/migrations/` | PostgreSQL / Supabase schema (`001`–`004`) |
| `database/seeds/` | SQL seeds (none shipped yet) |
| `scripts/apply_migrations.py` | Migration runner (`schema_migrations` tracker) |
| `github/` | GitHub operator checklist (MVP token connect) |
| `vercel/` | Vercel operator checklist (connect + optional web host) |

Root companions: `docker-compose.yml` (includes this compose file), `render.yaml`
(API on Render), `.env.example`, `.github/workflows/ci.yml`.

Provisioning guide: [`docs/database-provisioning.md`](../docs/database-provisioning.md).

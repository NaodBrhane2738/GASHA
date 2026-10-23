# Database provisioning (DevOps)

How GASHA gets a PostgreSQL schema. Source of truth for SQL files:
`infra/database/migrations/`. Runner: `infra/scripts/apply_migrations.py`.

## What creates the schema

| Path | Creates tables? |
|------|-----------------|
| SQLite (`GASHA_DB_DIALECT=sqlite`, default for host API) | Yes — API `sql_engine.init_schema()` |
| Postgres / Supabase (`GASHA_DB_DIALECT=postgres`) | **No** — API only checks required tables |
| Docker Compose `postgres` service | Creates empty DB/user only |
| `python infra/scripts/apply_migrations.py` | Applies `001`–`004` and records them in `schema_migrations` |

Compose does **not** run migrations automatically. The API container will fail its
Postgres schema check until migrations have been applied to `DATABASE_URL`.

## Documented target: Supabase Session pooler

1. Set `DATABASE_URL` to the **Session pooler** URI (port `5432`), not the
   direct `db.<ref>.supabase.co` host (IPv6-only on free plans).
2. From the repo root, with the API venv active (`pip install -r apps/api/requirements.txt`):

```bash
python infra/scripts/apply_migrations.py --status
python infra/scripts/apply_migrations.py --yes
python scripts/dev/check_supabase.py   # optional API-level table probe
```

Or: `python scripts/dev/migrate.py --yes`

## Local Compose PostgreSQL (blocked without team decision)

Migrations `001`–`003` create policies `TO service_role`. That role exists on
Supabase. Stock `postgres:17-alpine` in Compose typically does **not**.

**This repository will not create that role or rewrite those policies without an
explicit team/security decision.** Until then:

- Prefer provisioning against **Supabase** (above), or
- Run the API with SQLite / memory for local demos (`run_demo.py`, or unset
  postgres dialect).

Do **not** claim “compose Postgres is fully provisioned” until migrations have
been applied successfully against that instance in a disposable test and the
`service_role` decision is resolved.

## Tracking and safety

- Applied files are listed in `schema_migrations` (filename primary key).
- `--status` / `--dry-run` only read the tracker (they do not create tables or
  enable RLS). The tracker is created on the first apply.
- Each file runs in a transaction with the tracking insert; failure rolls back
  that file only.
- Re-running the runner is safe; already-applied filenames are skipped.
- There are no down-migrations. Rollback = restore a backup or recreate the
  Compose volume (`docker compose down -v` destroys local data).
- This runner never creates `service_role` or rewrites RLS policies.

## Related env vars

See `docs/environment-variables.md`: `DATABASE_URL`, `GASHA_DB_DIALECT`,
`GASHA_STORAGE_BACKEND`, `GASHA_TEST_DATABASE_URL` (scratch DB for integration
tests — never the demo database).

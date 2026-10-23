# `scripts/` — developer automation (DevOps)

| Path | Purpose |
|------|---------|
| `setup/setup_local.py` | Copy `.env.example` → `.env` if missing; print prerequisite status |
| `dev/generate_secrets.py` | Print strong secrets (not saved) |
| `dev/check_supabase.py` | Probe Supabase tables (needs keys in `.env`) |
| `dev/migrate.py` | Wrapper for `infra/scripts/apply_migrations.py` |
| `demo/` | Demo launcher, preflight, reset, attack scenarios |
| `reset/reset_local.py` | Delegates to `demo/reset_local.py` (confirm / `--yes`) |
| `seed/seed.py` | Reports SQL seeds status (none shipped; `--require-sql` fails if empty) |
| `test/run_checks.py` | Contracts / web / pytest / ruff checks |

Nothing here deploys to production or applies destructive DB resets to Postgres.

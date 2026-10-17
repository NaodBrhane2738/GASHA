-- ==============================================================================
-- Migration: 003_create_users_and_refresh_tokens.sql
-- Description: Postgres versions of the `users` and `refresh_tokens` tables that the
--              SQLite engine (apps/api/app/db/sql_engine.py) already creates.
--              Columns and types match the SQLite versions on purpose, so the
--              backend code can move to Postgres with minimal changes.
-- Target: Supabase / PostgreSQL. Safe to run more than once.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    full_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- Row level security: these tables hold password hashes, so the public/anon key
-- must never be able to read them. Only the backend's service role may.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS service_role_users_all ON users;
CREATE POLICY service_role_users_all ON users FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS service_role_refresh_tokens_all ON refresh_tokens;
CREATE POLICY service_role_refresh_tokens_all ON refresh_tokens FOR ALL TO service_role USING (true) WITH CHECK (true);
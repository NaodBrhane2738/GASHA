-- ==============================================================================
-- Migration: 004_add_audit_details_and_unique_sequence.sql
-- Description: Closes the gap between the SQLite engine and these migrations.
--   1. response_audit_log.details: the audit trail stores redacted event details
--      (and includes them in the tamper-evident hash), but migration 002 never
--      created the column.
--   2. A unique (environment_id, sequence_number): the hash chain relies on one
--      entry per sequence number, so the database should enforce it.
-- Target: Supabase / PostgreSQL. Safe to run more than once.
-- ==============================================================================

ALTER TABLE response_audit_log ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}';

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_log_env_seq
    ON response_audit_log (environment_id, sequence_number);
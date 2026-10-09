-- ==============================================================================
-- Migration: 002_create_investigations_and_responses.sql
-- Description: Creates relational schema for deterministic investigations,
--              active response proposals, and cryptographic audit hash logs.
-- Target: Supabase / PostgreSQL
-- ==============================================================================

-- 1. Investigations Table
CREATE TABLE IF NOT EXISTS investigations (
    incident_id TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    summary TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence_score NUMERIC(3, 2) NOT NULL,
    attack_story JSONB NOT NULL,
    grounded_evidence JSONB NOT NULL DEFAULT '[]',
    recommendations JSONB NOT NULL DEFAULT '[]',
    generated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_investigations_env ON investigations(environment_id);

-- 2. Response Actions Table
CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    action_type TEXT NOT NULL CHECK (action_type IN ('BLOCK_SOURCE', 'DISABLE_SESSION', 'ISOLATE_RESOURCE')),
    target_type TEXT NOT NULL CHECK (target_type IN ('IP_ADDRESS', 'SESSION_ID', 'USER_SESSION', 'ASSET_ID')),
    target_identifier TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'PROPOSED', 'PENDING_APPROVAL', 'APPROVED', 'REJECTED',
        'EXECUTING', 'SUCCEEDED', 'FAILED', 'VERIFICATION_FAILED',
        'CANCELLED', 'PENDING', 'SUCCESS', 'REVERTED'
    )) DEFAULT 'PENDING_APPROVAL',
    reason TEXT NOT NULL,
    supporting_evidence_ids TEXT[] NOT NULL DEFAULT '{}',
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    proposed_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ,
    approved_by TEXT,
    executed_at TIMESTAMPTZ,
    execution_message TEXT,
    verification_status TEXT,
    verification_message TEXT,
    audit_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_response_actions_env ON response_actions(environment_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_response_actions_status ON response_actions(status);

-- 3. Cryptographic Tamper-Evident Audit Trail Table
CREATE TABLE IF NOT EXISTS response_audit_log (
    audit_id TEXT PRIMARY KEY,
    sequence_number INT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    incident_id TEXT NOT NULL,
    response_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_identifier TEXT NOT NULL,
    outcome TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_env_seq ON response_audit_log(environment_id, sequence_number);

-- 4. Row Level Security (RLS) Configuration
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_audit_log ENABLE ROW LEVEL SECURITY;

-- Service Role Full Access Policies
CREATE POLICY service_role_investigations_all ON investigations FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_response_actions_all ON response_actions FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_audit_log_all ON response_audit_log FOR ALL TO service_role USING (true) WITH CHECK (true);

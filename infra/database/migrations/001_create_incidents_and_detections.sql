-- ==============================================================================
-- Migration: 001_create_incidents_and_detections.sql
-- Description: Creates relational schema for detections and correlated incidents.
-- Target: Supabase / PostgreSQL
-- ==============================================================================

-- 1. Detections Table
CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_description TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    confidence NUMERIC(3, 2) NOT NULL,
    primary_asset_id TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    incident_id TEXT,
    matched_event_ids TEXT[] NOT NULL DEFAULT '{}',
    evidence_summary TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_detections_env ON detections(environment_id);
CREATE INDEX IF NOT EXISTS idx_detections_incident ON detections(incident_id);
CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections(created_at DESC);

-- 2. Incidents Table
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED')) DEFAULT 'ACTIVE',
    primary_affected_asset_id TEXT NOT NULL,
    related_asset_ids TEXT[] NOT NULL DEFAULT '{}',
    detection_event_ids TEXT[] NOT NULL DEFAULT '{}',
    attack_path_id TEXT,
    summary TEXT,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    correlation_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_incidents_env ON incidents(environment_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_corr_key ON incidents(environment_id, correlation_key);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at DESC);

-- 3. Row Level Security (RLS) Configuration
ALTER TABLE detections ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;

-- Service Role Full Access Policies
DROP POLICY IF EXISTS service_role_detections_all ON detections;
CREATE POLICY service_role_detections_all ON detections FOR ALL TO service_role USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS service_role_incidents_all ON incidents;
CREATE POLICY service_role_incidents_all ON incidents FOR ALL TO service_role USING (true) WITH CHECK (true);
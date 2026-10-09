-- ==============================================================================
-- Migration: 003_create_assets_findings_and_state.sql
-- Description: Creates relational schema for canonical assets, topology relationships,
--              cloud connections, discovery runs, security assessment findings,
--              risk scores, attack paths, and persistent telemetry deduplication.
-- Target: Supabase / PostgreSQL
-- ==============================================================================

-- 1. Assets Table
CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    criticality TEXT NOT NULL CHECK (criticality IN ('TIER_0', 'TIER_1', 'TIER_2', 'TIER_3')),
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    source TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    is_publicly_exposed BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT uq_assets_env_source_name UNIQUE (environment_id, source, name)
);

CREATE INDEX IF NOT EXISTS idx_assets_env ON assets(environment_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);

-- 2. Asset Relationships Table
CREATE TABLE IF NOT EXISTS asset_relationships (
    id TEXT PRIMARY KEY,
    source_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT uq_rel_env_endpoints_type UNIQUE (environment_id, source_asset_id, target_asset_id, type)
);

CREATE INDEX IF NOT EXISTS idx_relationships_env ON asset_relationships(environment_id);

-- 3. Cloud Connections Table
CREATE TABLE IF NOT EXISTS cloud_connections (
    id TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    provider TEXT NOT NULL CHECK (provider IN ('VERCEL', 'GITHUB')),
    account_name TEXT,
    scope TEXT,
    encrypted_token TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('CONNECTED', 'DISCONNECTED', 'ERROR')) DEFAULT 'CONNECTED',
    resource_count INT NOT NULL DEFAULT 0,
    last_sync_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    CONSTRAINT uq_connections_env_provider UNIQUE (environment_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_connections_env ON cloud_connections(environment_id);

-- 4. Discovery Runs Table
CREATE TABLE IF NOT EXISTS discovery_runs (
    id TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'IN_PROGRESS', 'COMPLETED', 'PARTIAL', 'FAILED')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    completed_at TIMESTAMPTZ,
    assets_discovered INT NOT NULL DEFAULT 0,
    relationships_discovered INT NOT NULL DEFAULT 0,
    errors TEXT[] NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_discovery_runs_env_started ON discovery_runs(environment_id, started_at DESC);

-- 5. Vulnerabilities / Findings Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    rule_id TEXT,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cvss_score NUMERIC(3, 1),
    category TEXT NOT NULL,
    remediation_guidance TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'MITIGATED', 'SUPPRESSED')) DEFAULT 'OPEN',
    evidence JSONB NOT NULL DEFAULT '{}',
    is_stale BOOLEAN NOT NULL DEFAULT FALSE,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_env ON vulnerabilities(environment_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_asset ON vulnerabilities(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(status);

-- 6. Risk Snapshots & History Tables
CREATE TABLE IF NOT EXISTS risk_snapshots (
    environment_id TEXT PRIMARY KEY,
    overall_score NUMERIC(5, 2) NOT NULL,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    critical_assets_at_risk_count INT NOT NULL DEFAULT 0,
    high_risk_vulnerabilities_count INT NOT NULL DEFAULT 0,
    active_attack_paths_count INT NOT NULL DEFAULT 0,
    contributors JSONB NOT NULL DEFAULT '[]',
    explanation JSONB
);

CREATE TABLE IF NOT EXISTS risk_history (
    id BIGSERIAL PRIMARY KEY,
    environment_id TEXT NOT NULL,
    score NUMERIC(5, 2) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    trigger_event TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_risk_history_env ON risk_history(environment_id, timestamp DESC);

-- 7. Attack Paths Table
CREATE TABLE IF NOT EXISTS attack_paths (
    id TEXT NOT NULL,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    entry_point_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    path_score NUMERIC(5, 2) NOT NULL,
    nodes JSONB NOT NULL DEFAULT '[]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    reachability TEXT NOT NULL CHECK (reachability IN ('REACHABLE', 'BLOCKED', 'UNKNOWN')) DEFAULT 'REACHABLE',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    mitigated_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (environment_id, id)
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_env ON attack_paths(environment_id);

-- 8. Investigation Timelines Table
CREATE TABLE IF NOT EXISTS investigation_timelines (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    timeline_data JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    PRIMARY KEY (incident_id, environment_id)
);

-- 9. Telemetry Deduplication Table
CREATE TABLE IF NOT EXISTS telemetry_deduplication (
    dedup_key TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    detections JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_dedup_ts ON telemetry_deduplication(timestamp);

-- 10. Users Directory Table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('security_analyst', 'security_operator', 'admin', 'emergency_admin')),
    environment_id TEXT NOT NULL DEFAULT 'env-prod',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- 11. Refresh Tokens Table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    environment_id TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

-- Row Level Security (RLS) Configuration
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE cloud_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE investigation_timelines ENABLE ROW LEVEL SECURITY;
ALTER TABLE telemetry_deduplication ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;

-- Service Role Full Access Policies
CREATE POLICY service_role_assets_all ON assets FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_asset_relationships_all ON asset_relationships FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_cloud_connections_all ON cloud_connections FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_discovery_runs_all ON discovery_runs FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_vulnerabilities_all ON vulnerabilities FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_risk_snapshots_all ON risk_snapshots FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_risk_history_all ON risk_history FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_attack_paths_all ON attack_paths FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_investigation_timelines_all ON investigation_timelines FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_telemetry_deduplication_all ON telemetry_deduplication FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_users_all ON users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_refresh_tokens_all ON refresh_tokens FOR ALL TO service_role USING (true) WITH CHECK (true);

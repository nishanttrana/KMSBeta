BEGIN;

-- Key Rotation Metrics Table
-- Tracks all key rotation operations with metrics for analytics dashboard
CREATE TABLE IF NOT EXISTS key_rotation_metrics (
    rotation_id         TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    scheduled_date      TIMESTAMPTZ NOT NULL,
    actual_date         TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'scheduled', -- scheduled, in_progress, completed, failed, cancelled
    duration_ms         BIGINT,
    reason              TEXT,
    initiated_by        TEXT NOT NULL,
    completed_by        TEXT,
    error_details       TEXT,
    old_version         INTEGER,
    new_version         INTEGER,
    rollback_attempted  BOOLEAN DEFAULT FALSE,
    metadata_json       JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, rotation_id)
);

CREATE INDEX IF NOT EXISTS idx_rotation_metrics_key ON key_rotation_metrics(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_rotation_metrics_scheduled ON key_rotation_metrics(tenant_id, scheduled_date);
CREATE INDEX IF NOT EXISTS idx_rotation_metrics_status ON key_rotation_metrics(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_rotation_metrics_created ON key_rotation_metrics(tenant_id, created_at DESC);

-- Key Health Scores Table
-- Maintains aggregate health scoring for each key
CREATE TABLE IF NOT EXISTS key_health_scores (
    key_id              TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    health_score        INTEGER NOT NULL DEFAULT 100, -- 0-100 overall health
    entropy_score       INTEGER NOT NULL DEFAULT 100,
    age_score           INTEGER NOT NULL DEFAULT 100,
    usage_score         INTEGER NOT NULL DEFAULT 100,
    algorithm_score     INTEGER NOT NULL DEFAULT 100,
    backup_status       TEXT NOT NULL DEFAULT 'unknown', -- unknown, verified, stale, missing
    rotation_overdue    BOOLEAN DEFAULT FALSE,
    expiry_imminent     BOOLEAN DEFAULT FALSE,
    compliance_warnings JSONB DEFAULT '[]'::jsonb,
    recommended_actions JSONB DEFAULT '[]'::jsonb,
    last_audit_date     TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, key_id)
);

CREATE INDEX IF NOT EXISTS idx_health_scores_score ON key_health_scores(tenant_id, health_score);
CREATE INDEX IF NOT EXISTS idx_health_scores_updated ON key_health_scores(tenant_id, updated_at DESC);

-- Key Inventory Table
-- Comprehensive inventory of all keys with metadata
CREATE TABLE IF NOT EXISTS key_inventory (
    key_id              TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    key_name            TEXT NOT NULL,
    key_type            TEXT NOT NULL,
    algorithm           TEXT NOT NULL,
    owner               TEXT NOT NULL,
    status              TEXT NOT NULL,
    created_date        TIMESTAMPTZ NOT NULL,
    last_used           TIMESTAMPTZ,
    last_rotated        TIMESTAMPTZ,
    rotation_frequency  TEXT, -- monthly, quarterly, annually, never
    next_rotation       TIMESTAMPTZ,
    expiry_date         TIMESTAMPTZ,
    backup_verified_at  TIMESTAMPTZ,
    hsm_stored          BOOLEAN DEFAULT FALSE,
    cloud_provider      TEXT, -- aws, azure, gcp, etc
    region              TEXT,
    compliance_tags     JSONB DEFAULT '[]'::jsonb,
    metadata_json       JSONB DEFAULT '{}',
    discovered_via      TEXT, -- api_scan, dependency_map, manual, etc
    discovery_timestamp TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, key_id)
);

CREATE INDEX IF NOT EXISTS idx_inventory_status ON key_inventory(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_inventory_owner ON key_inventory(tenant_id, owner);
CREATE INDEX IF NOT EXISTS idx_inventory_algorithm ON key_inventory(tenant_id, algorithm);
CREATE INDEX IF NOT EXISTS idx_inventory_created ON key_inventory(tenant_id, created_date DESC);
CREATE INDEX IF NOT EXISTS idx_inventory_last_used ON key_inventory(tenant_id, last_used DESC);
CREATE INDEX IF NOT EXISTS idx_inventory_expiry ON key_inventory(tenant_id, expiry_date) WHERE status = 'active';

-- Key Dependencies Table
-- Maps keys to their dependent services and applications
CREATE TABLE IF NOT EXISTS key_dependencies (
    dependency_id       TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    service_id          TEXT NOT NULL,
    app_id              TEXT,
    dependency_type     TEXT NOT NULL, -- encryption, signing, wrapping, authentication, etc
    criticality         TEXT NOT NULL DEFAULT 'medium', -- critical, high, medium, low
    last_verified       TIMESTAMPTZ,
    verification_status TEXT DEFAULT 'unknown', -- unknown, verified, stale, broken
    usage_frequency     TEXT DEFAULT 'unknown', -- high, medium, low, unknown
    last_access_log_id  TEXT,
    metadata_json       JSONB DEFAULT '{}',
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, dependency_id)
);

CREATE INDEX IF NOT EXISTS idx_dependencies_key ON key_dependencies(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_service ON key_dependencies(tenant_id, service_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_criticality ON key_dependencies(tenant_id, criticality);
CREATE INDEX IF NOT EXISTS idx_dependencies_verified ON key_dependencies(tenant_id, last_verified DESC);

-- Compromise Events Table
-- Tracks potential or confirmed key compromise events
CREATE TABLE IF NOT EXISTS compromise_events (
    event_id            TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    cve_id              TEXT,
    threat_type         TEXT NOT NULL, -- cve, breach, suspicious_activity, key_exposure, algorithm_weakness
    severity            TEXT NOT NULL, -- critical, high, medium, low, info
    detection_date      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_date      TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'pending', -- pending, investigating, confirmed, false_positive, resolved
    remediation_plan    TEXT,
    remediation_status  TEXT DEFAULT 'not_started', -- not_started, in_progress, completed
    remediation_date    TIMESTAMPTZ,
    affected_systems    JSONB DEFAULT '[]'::jsonb,
    notifications_sent  JSONB DEFAULT '[]'::jsonb,
    root_cause          TEXT,
    detection_source    TEXT, -- feed_sync, usage_anomaly, external_report, cve_database
    metadata_json       JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_compromise_key ON compromise_events(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_compromise_status ON compromise_events(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_compromise_severity ON compromise_events(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_compromise_created ON compromise_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_compromise_cve ON compromise_events(tenant_id, cve_id) WHERE cve_id IS NOT NULL;

-- Key Analytics Metrics Table
-- Time-series metrics for analytics (rotation rates, usage patterns, etc)
CREATE TABLE IF NOT EXISTS key_analytics_metrics (
    metric_id           TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    metric_type         TEXT NOT NULL, -- rotation_count, usage_count, failure_rate, access_latency, etc
    value               FLOAT NOT NULL,
    aggregation_period  TEXT NOT NULL DEFAULT 'hourly', -- hourly, daily, weekly, monthly
    timestamp           TIMESTAMPTZ NOT NULL,
    metadata_json       JSONB DEFAULT '{}',
    PRIMARY KEY (tenant_id, metric_id)
);

CREATE INDEX IF NOT EXISTS idx_analytics_key ON key_analytics_metrics(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_analytics_type ON key_analytics_metrics(tenant_id, metric_type);
CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON key_analytics_metrics(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_analytics_period ON key_analytics_metrics(tenant_id, aggregation_period, timestamp DESC);

-- Enable Row Level Security on new tables
ALTER TABLE key_rotation_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_health_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE compromise_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_analytics_metrics ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_rotation_metrics') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_rotation_metrics ON key_rotation_metrics USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_health_scores') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_health_scores ON key_health_scores USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_inventory') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_inventory ON key_inventory USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_dependencies') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_dependencies ON key_dependencies USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_compromise_events') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_compromise_events ON compromise_events USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_analytics_metrics') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_analytics_metrics ON key_analytics_metrics USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;

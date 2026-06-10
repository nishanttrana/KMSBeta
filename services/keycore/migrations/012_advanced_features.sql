BEGIN;

-- key_health_scores and key_dependencies already created in 010_tier1_features.sql; skipped here.

-- Key scheduling jobs: batch / orchestrated operations
CREATE TABLE IF NOT EXISTS key_scheduling_jobs (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    job_type        TEXT NOT NULL,  -- "batch_rotate", "batch_archive", "batch_expire", "workflow"
    cron_expr       TEXT NOT NULL DEFAULT '',
    target_filter   TEXT NOT NULL DEFAULT '',
    payload         JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at     TIMESTAMPTZ,
    last_run_status TEXT NOT NULL DEFAULT '',
    last_run_error  TEXT NOT NULL DEFAULT '',
    next_run_at     TIMESTAMPTZ,
    run_count       INTEGER NOT NULL DEFAULT 0,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_key_scheduling_jobs_tenant ON key_scheduling_jobs(tenant_id);

-- KDF configs: Key Derivation Function configurations
CREATE TABLE IF NOT EXISTS kdf_configs (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    name         TEXT NOT NULL,
    algorithm    TEXT NOT NULL, -- "hkdf-sha256", "pbkdf2-sha512", "scrypt", "argon2id"
    params       JSONB NOT NULL DEFAULT '{}',
    purpose      TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_kdf_configs_tenant ON kdf_configs(tenant_id);

-- KDF derivation log
CREATE TABLE IF NOT EXISTS kdf_derivation_log (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    config_id    TEXT NOT NULL,
    source_key   TEXT NOT NULL DEFAULT '',
    purpose      TEXT NOT NULL DEFAULT '',
    context_hash TEXT NOT NULL DEFAULT '',
    performed_by TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_kdf_derivation_log_tenant ON kdf_derivation_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_kdf_derivation_log_config ON kdf_derivation_log(tenant_id, config_id);

-- Key binding configs: hardware attestation + geolocation constraints
CREATE TABLE IF NOT EXISTS key_binding_configs (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    binding_type        TEXT NOT NULL, -- "hardware", "geolocation", "network", "tpm", "combined"
    allowed_pcr_values  JSONB NOT NULL DEFAULT '[]',
    allowed_regions     JSONB NOT NULL DEFAULT '[]',
    allowed_ip_cidrs    JSONB NOT NULL DEFAULT '[]',
    tpm_endorsement_key TEXT NOT NULL DEFAULT '',
    require_attestation BOOLEAN NOT NULL DEFAULT FALSE,
    enforcement_mode    TEXT NOT NULL DEFAULT 'audit', -- "audit", "enforce"
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_key_binding_configs_key ON key_binding_configs(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_key_binding_configs_tenant ON key_binding_configs(tenant_id);

-- Key sharing tokens: fine-grained temporary access delegation
CREATE TABLE IF NOT EXISTS key_sharing_tokens (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    grantee_id      TEXT NOT NULL DEFAULT '',
    grantee_type    TEXT NOT NULL DEFAULT 'user', -- "user", "service", "external"
    operations      JSONB NOT NULL DEFAULT '["encrypt","decrypt"]',
    max_uses        INTEGER NOT NULL DEFAULT 0, -- 0 = unlimited
    uses_count      INTEGER NOT NULL DEFAULT 0,
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_by      TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_key_sharing_tokens_tenant ON key_sharing_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_key_sharing_tokens_key ON key_sharing_tokens(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_key_sharing_tokens_hash ON key_sharing_tokens(token_hash);

-- Key metadata extensions: classification, tagging, enrichment
CREATE TABLE IF NOT EXISTS key_metadata_ext (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL,
    key_id           TEXT NOT NULL,
    classification   TEXT NOT NULL DEFAULT 'internal', -- "public", "internal", "confidential", "restricted"
    data_category    TEXT NOT NULL DEFAULT '',
    business_unit    TEXT NOT NULL DEFAULT '',
    project          TEXT NOT NULL DEFAULT '',
    cost_center      TEXT NOT NULL DEFAULT '',
    criticality      TEXT NOT NULL DEFAULT 'medium', -- "low", "medium", "high", "critical"
    retention_years  INTEGER NOT NULL DEFAULT 7,
    custom_fields    JSONB NOT NULL DEFAULT '{}',
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_key_metadata_ext_key ON key_metadata_ext(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_key_metadata_ext_tenant ON key_metadata_ext(tenant_id);

-- Edge device registry
CREATE TABLE IF NOT EXISTS edge_devices (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    device_type     TEXT NOT NULL DEFAULT 'iot', -- "iot", "edge-gateway", "embedded", "mobile"
    platform        TEXT NOT NULL DEFAULT '',
    hw_fingerprint  TEXT NOT NULL DEFAULT '',
    assigned_keys   JSONB NOT NULL DEFAULT '[]',
    last_seen_at    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'registered', -- "registered", "active", "revoked"
    offline_bundle  BYTEA,
    bundle_expires  TIMESTAMPTZ,
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_edge_devices_tenant ON edge_devices(tenant_id);

-- Rotation analytics: aggregated stats (rebuilt periodically)
CREATE TABLE IF NOT EXISTS rotation_analytics_snapshot (
    id                    TEXT PRIMARY KEY,
    tenant_id             TEXT NOT NULL,
    period_start          TIMESTAMPTZ NOT NULL,
    period_end            TIMESTAMPTZ NOT NULL,
    total_keys            INTEGER NOT NULL DEFAULT 0,
    rotated_count         INTEGER NOT NULL DEFAULT 0,
    failed_count          INTEGER NOT NULL DEFAULT 0,
    overdue_count         INTEGER NOT NULL DEFAULT 0,
    avg_rotation_days     NUMERIC(8,2) NOT NULL DEFAULT 0,
    p95_rotation_ms       BIGINT NOT NULL DEFAULT 0,
    by_algorithm          JSONB NOT NULL DEFAULT '{}',
    by_status             JSONB NOT NULL DEFAULT '{}',
    computed_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_rotation_analytics_tenant ON rotation_analytics_snapshot(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rotation_analytics_period ON rotation_analytics_snapshot(tenant_id, period_start);

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'key_scheduling_jobs' AND policyname = 'tenant_isolation_key_scheduling_jobs'
    ) THEN
        ALTER TABLE key_scheduling_jobs ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_key_scheduling_jobs ON key_scheduling_jobs USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'kdf_configs' AND policyname = 'tenant_isolation_kdf_configs'
    ) THEN
        ALTER TABLE kdf_configs ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_kdf_configs ON kdf_configs USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'kdf_derivation_log' AND policyname = 'tenant_isolation_kdf_derivation_log'
    ) THEN
        ALTER TABLE kdf_derivation_log ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_kdf_derivation_log ON kdf_derivation_log USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'key_binding_configs' AND policyname = 'tenant_isolation_key_binding_configs'
    ) THEN
        ALTER TABLE key_binding_configs ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_key_binding_configs ON key_binding_configs USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'key_sharing_tokens' AND policyname = 'tenant_isolation_key_sharing_tokens'
    ) THEN
        ALTER TABLE key_sharing_tokens ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_key_sharing_tokens ON key_sharing_tokens USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'key_metadata_ext' AND policyname = 'tenant_isolation_key_metadata_ext'
    ) THEN
        ALTER TABLE key_metadata_ext ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_key_metadata_ext ON key_metadata_ext USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'edge_devices' AND policyname = 'tenant_isolation_edge_devices'
    ) THEN
        ALTER TABLE edge_devices ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_edge_devices ON edge_devices USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'rotation_analytics_snapshot' AND policyname = 'tenant_isolation_rotation_analytics_snapshot'
    ) THEN
        ALTER TABLE rotation_analytics_snapshot ENABLE ROW LEVEL SECURITY;
        EXECUTE 'CREATE POLICY tenant_isolation_rotation_analytics_snapshot ON rotation_analytics_snapshot USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;

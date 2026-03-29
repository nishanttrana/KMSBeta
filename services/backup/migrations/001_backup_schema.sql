CREATE TABLE IF NOT EXISTS backup_policies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT 'all_keys', -- all_keys, critical_keys, tagged
    tag_filter TEXT NOT NULL DEFAULT '',
    cron_expr TEXT NOT NULL DEFAULT '0 1 * * *',
    retention_days INT NOT NULL DEFAULT 90,
    encrypt_backup BOOLEAN NOT NULL DEFAULT TRUE,
    compress BOOLEAN NOT NULL DEFAULT TRUE,
    destination TEXT NOT NULL DEFAULT 'local', -- local, s3, gcs, azure_blob
    destination_uri TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS backup_runs (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    policy_id TEXT,
    policy_name TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    scope TEXT NOT NULL DEFAULT 'all_keys',
    total_keys INT NOT NULL DEFAULT 0,
    backed_up_keys INT NOT NULL DEFAULT 0,
    failed_keys INT NOT NULL DEFAULT 0,
    backup_size_bytes BIGINT NOT NULL DEFAULT 0,
    destination TEXT NOT NULL DEFAULT 'local',
    destination_path TEXT NOT NULL DEFAULT '',
    triggered_by TEXT NOT NULL DEFAULT 'manual',
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    error TEXT,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS backup_restore_points (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_count INT NOT NULL DEFAULT 0,
    backup_size_bytes BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    checksum TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'available', -- available, restoring, expired, deleted
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_backup_runs_tenant ON backup_runs(tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_restore_points_tenant ON backup_restore_points(tenant_id, created_at DESC);

-- Guardians for key ceremony
CREATE TABLE IF NOT EXISTS ceremony_guardians (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'guardian',
    status TEXT NOT NULL DEFAULT 'active',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

-- Key ceremonies
CREATE TABLE IF NOT EXISTS ceremonies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- key_generation, key_recovery, key_destruction, root_rotation
    threshold INT NOT NULL,
    total_shares INT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    key_id TEXT,
    key_name TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

-- Ceremony shares (per guardian)
CREATE TABLE IF NOT EXISTS ceremony_shares (
    ceremony_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    guardian_id TEXT NOT NULL,
    guardian_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending, submitted, verified
    submitted_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, ceremony_id, guardian_id)
);

-- Rotation policies
CREATE TABLE IF NOT EXISTS rotation_policies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'key',
    target_filter TEXT NOT NULL DEFAULT '',
    interval_days INT NOT NULL DEFAULT 90,
    cron_expr TEXT,
    auto_rotate BOOLEAN NOT NULL DEFAULT FALSE,
    notify_days_before INT NOT NULL DEFAULT 7,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    status TEXT NOT NULL DEFAULT 'active',
    last_rotation_at TIMESTAMPTZ,
    next_rotation_at TIMESTAMPTZ,
    total_rotations INT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

-- Rotation run history
CREATE TABLE IF NOT EXISTS rotation_runs (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'key',
    status TEXT NOT NULL DEFAULT 'running',
    triggered_by TEXT NOT NULL DEFAULT 'schedule',
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    error TEXT,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_rotation_policies_tenant ON rotation_policies(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_rotation_runs_tenant_policy ON rotation_runs(tenant_id, policy_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_ceremony_shares_ceremony ON ceremony_shares(tenant_id, ceremony_id);

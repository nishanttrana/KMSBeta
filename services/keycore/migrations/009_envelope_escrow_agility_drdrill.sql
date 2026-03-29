-- Envelope encryption: KEKs (Key Encryption Keys)
CREATE TABLE IF NOT EXISTS envelope_keks (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    version INT NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

-- DEKs (Data Encryption Keys) wrapped by KEKs
CREATE TABLE IF NOT EXISTS envelope_deks (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    kek_id TEXT NOT NULL,
    kek_name TEXT NOT NULL,
    name TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    purpose TEXT NOT NULL DEFAULT 'field_encryption',
    owner_service TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

-- Rewrap jobs
CREATE TABLE IF NOT EXISTS envelope_rewrap_jobs (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    old_kek_id TEXT NOT NULL,
    new_kek_id TEXT NOT NULL,
    total_deks INT NOT NULL DEFAULT 0,
    processed_deks INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

-- Key Escrow guardians
CREATE TABLE IF NOT EXISTS escrow_guardians (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    organization TEXT NOT NULL DEFAULT '',
    notary_cert_fingerprint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    added_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

-- Escrow policies
CREATE TABLE IF NOT EXISTS escrow_policies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    key_filter TEXT NOT NULL DEFAULT '',
    threshold INT NOT NULL DEFAULT 2,
    guardian_ids_json TEXT NOT NULL DEFAULT '[]',
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    jurisdiction TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    escrow_count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id)
);

-- Escrowed keys
CREATE TABLE IF NOT EXISTS escrowed_keys (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT '',
    guardian_ids_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    escrowed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    escrowed_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

-- Recovery requests
CREATE TABLE IF NOT EXISTS escrow_recovery_requests (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    escrow_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_name TEXT NOT NULL,
    requestor TEXT NOT NULL,
    reason TEXT NOT NULL,
    legal_reference TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    required_approvals INT NOT NULL DEFAULT 2,
    approvals_json TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

-- Crypto agility: migration plans
CREATE TABLE IF NOT EXISTS agility_migration_plans (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    from_algorithm TEXT NOT NULL,
    to_algorithm TEXT NOT NULL,
    affected_keys INT NOT NULL DEFAULT 0,
    completed_keys INT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'planned',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    target_date TIMESTAMPTZ
);

-- DR drill schedules
CREATE TABLE IF NOT EXISTS dr_drill_schedules (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cron_expr TEXT NOT NULL DEFAULT '0 2 * * 0',
    drill_type TEXT NOT NULL DEFAULT 'key_restore',
    scope TEXT NOT NULL DEFAULT 'all_keys',
    target_env TEXT NOT NULL DEFAULT 'staging',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

-- DR drill runs
CREATE TABLE IF NOT EXISTS dr_drill_runs (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    schedule_id TEXT,
    schedule_name TEXT,
    drill_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    rto_seconds INT,
    rpo_seconds INT,
    total_keys INT NOT NULL DEFAULT 0,
    restored_keys INT NOT NULL DEFAULT 0,
    failed_keys INT NOT NULL DEFAULT 0,
    steps_json TEXT NOT NULL DEFAULT '[]',
    triggered_by TEXT NOT NULL DEFAULT 'manual',
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_envelope_deks_kek ON envelope_deks(tenant_id, kek_id);
CREATE INDEX IF NOT EXISTS idx_escrowed_keys_policy ON escrowed_keys(tenant_id, policy_id);
CREATE INDEX IF NOT EXISTS idx_dr_drill_runs_tenant ON dr_drill_runs(tenant_id, started_at DESC);

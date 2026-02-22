CREATE TABLE IF NOT EXISTS pqc_readiness_scans (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    status TEXT NOT NULL,
    total_assets INTEGER NOT NULL DEFAULT 0,
    pqc_ready_assets INTEGER NOT NULL DEFAULT 0,
    hybrid_assets INTEGER NOT NULL DEFAULT 0,
    classical_assets INTEGER NOT NULL DEFAULT 0,
    average_qsl REAL NOT NULL DEFAULT 0,
    readiness_score INTEGER NOT NULL DEFAULT 0,
    algorithm_summary_json TEXT NOT NULL DEFAULT '{}',
    timeline_status_json TEXT NOT NULL DEFAULT '{}',
    risk_items_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_pqc_scans_created ON pqc_readiness_scans (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS pqc_migration_plans (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    target_profile TEXT NOT NULL,
    timeline_standard TEXT NOT NULL,
    deadline TIMESTAMP,
    summary_json TEXT NOT NULL DEFAULT '{}',
    steps_json TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    executed_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_pqc_plans_created ON pqc_migration_plans (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS pqc_migration_runs (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    status TEXT NOT NULL,
    dry_run BOOLEAN NOT NULL DEFAULT FALSE,
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_pqc_runs_plan ON pqc_migration_runs (tenant_id, plan_id, created_at DESC);

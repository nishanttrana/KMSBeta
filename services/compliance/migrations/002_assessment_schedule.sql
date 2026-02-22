CREATE TABLE IF NOT EXISTS compliance_assessment_runs (
    tenant_id         TEXT NOT NULL,
    id                TEXT NOT NULL,
    trigger           TEXT NOT NULL DEFAULT 'manual',
    overall_score     INTEGER NOT NULL,
    framework_scores  TEXT NOT NULL DEFAULT '{}',
    findings_json     TEXT NOT NULL DEFAULT '[]',
    pqc_json          TEXT NOT NULL DEFAULT '{}',
    cert_metrics_json TEXT NOT NULL DEFAULT '{}',
    posture_json      TEXT NOT NULL DEFAULT '{}',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_assessment_runs_tenant_created
    ON compliance_assessment_runs (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS compliance_assessment_schedules (
    tenant_id   TEXT PRIMARY KEY,
    enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    frequency   TEXT NOT NULL DEFAULT 'daily',
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_compliance_assessment_schedules_due
    ON compliance_assessment_schedules (enabled, next_run_at);

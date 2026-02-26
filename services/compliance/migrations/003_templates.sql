ALTER TABLE compliance_assessment_runs
    ADD COLUMN IF NOT EXISTS template_id TEXT NOT NULL DEFAULT '';

ALTER TABLE compliance_assessment_runs
    ADD COLUMN IF NOT EXISTS template_name TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_compliance_assessment_runs_tenant_template_created
    ON compliance_assessment_runs (tenant_id, template_id, created_at DESC);

CREATE TABLE IF NOT EXISTS compliance_templates (
    tenant_id      TEXT NOT NULL,
    id             TEXT NOT NULL,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    frameworks_json TEXT NOT NULL DEFAULT '[]',
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_templates_tenant_updated
    ON compliance_templates (tenant_id, updated_at DESC);

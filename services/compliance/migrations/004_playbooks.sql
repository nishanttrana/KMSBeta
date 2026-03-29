-- Automated Incident Playbooks
CREATE TABLE IF NOT EXISTS compliance_playbooks (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    trigger_json TEXT NOT NULL DEFAULT '{}',
    actions_json TEXT NOT NULL DEFAULT '[]',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    run_count   INT NOT NULL DEFAULT 0,
    last_run_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_playbooks_tenant_created
    ON compliance_playbooks (tenant_id, created_at DESC);

-- Playbook Run History
CREATE TABLE IF NOT EXISTS compliance_playbook_runs (
    id             TEXT NOT NULL,
    playbook_id    TEXT NOT NULL,
    tenant_id      TEXT NOT NULL,
    trigger_event  TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'running',
    actions_run    INT NOT NULL DEFAULT 0,
    output         TEXT NOT NULL DEFAULT '',
    started_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_playbook_runs_playbook
    ON compliance_playbook_runs (tenant_id, playbook_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_compliance_playbook_runs_recent
    ON compliance_playbook_runs (tenant_id, started_at DESC);

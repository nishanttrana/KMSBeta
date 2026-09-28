-- Playbooks as the response layer (2.5.0-beta).
--
-- Runs keep the event they respond to (context_json), a result per action
-- (results_json), where to resume after a governance approval
-- (resume_index, approved_index, approval_request_id), the reporting
-- incident they answer, and the run they retry.
--
-- Connections hold the endpoints and credentials notification actions use,
-- sealed under the compliance master key from keycore (pkg/mek): one
-- envelope per connection, with only the name, type and endpoint host in
-- plaintext. Credentials that earlier releases kept inline in actions_json
-- are moved here at startup by the primary and recorded in
-- compliance_mek_exposure.
--
-- Schema only: the tables are replicated (pkg/clustercatalog).
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT 'user';
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS context_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS results_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS resume_index INT NOT NULL DEFAULT 0;
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS approved_index INT NOT NULL DEFAULT -1;
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS approval_request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS incident_id TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS retry_of TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_compliance_playbook_runs_approval
    ON compliance_playbook_runs (tenant_id, approval_request_id);
CREATE INDEX IF NOT EXISTS idx_compliance_playbook_runs_incident
    ON compliance_playbook_runs (tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS idx_compliance_playbook_runs_status
    ON compliance_playbook_runs (tenant_id, status, started_at DESC);

CREATE TABLE IF NOT EXISTS compliance_playbook_connections (
    tenant_id            TEXT NOT NULL,
    id                   TEXT NOT NULL,
    name                 TEXT NOT NULL,
    type                 TEXT NOT NULL,
    endpoint             TEXT NOT NULL DEFAULT '',
    fields_set           TEXT NOT NULL DEFAULT '[]',
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    creds_ciphertext     BYTEA,
    creds_data_iv        BYTEA,
    creds_wrapped_dek    BYTEA,
    creds_wrapped_dek_iv BYTEA,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS compliance_mek_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    mek_fingerprint TEXT NOT NULL,
    rewrapped       BIGINT NOT NULL DEFAULT 0,
    unreadable      BIGINT NOT NULL DEFAULT 0,
    migrated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS compliance_mek_exposure (
    tenant_id     TEXT NOT NULL,
    item_type     TEXT NOT NULL,
    item_id       TEXT NOT NULL,
    source        TEXT NOT NULL,
    exposed_since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP,
    remediation   TEXT NOT NULL DEFAULT '',
    remediated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, item_type, item_id)
);

CREATE TABLE IF NOT EXISTS policies (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    spec_type       TEXT NOT NULL,
    labels          TEXT NOT NULL DEFAULT '{}',
    yaml_document   TEXT NOT NULL,
    parsed_json     TEXT NOT NULL,
    current_version INTEGER NOT NULL DEFAULT 1,
    current_commit  TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    updated_by      TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(tenant_id, spec_type);

CREATE TABLE IF NOT EXISTS policy_versions (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL,
    policy_id          TEXT NOT NULL,
    version            INTEGER NOT NULL,
    commit_hash        TEXT NOT NULL,
    parent_commit_hash TEXT,
    change_type        TEXT NOT NULL,
    change_message     TEXT,
    yaml_document      TEXT NOT NULL,
    parsed_json        TEXT NOT NULL,
    created_by         TEXT NOT NULL,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, policy_id, version),
    UNIQUE (commit_hash)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_lookup ON policy_versions(tenant_id, policy_id, version DESC);

CREATE TABLE IF NOT EXISTS policy_evaluations (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    policy_id     TEXT,
    operation     TEXT NOT NULL,
    key_id        TEXT,
    decision      TEXT NOT NULL,
    reason        TEXT,
    request_json  TEXT NOT NULL,
    outcomes_json TEXT NOT NULL,
    occurred_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policy_evals_tenant ON policy_evaluations(tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_policy_evals_operation ON policy_evaluations(tenant_id, operation, occurred_at DESC);

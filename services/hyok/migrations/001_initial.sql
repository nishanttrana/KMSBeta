CREATE TABLE IF NOT EXISTS hyok_endpoints (
    tenant_id            TEXT NOT NULL,
    protocol             TEXT NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    auth_mode            TEXT NOT NULL DEFAULT 'mtls_or_jwt',
    policy_id            TEXT NOT NULL DEFAULT '',
    governance_required  BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_json        TEXT NOT NULL DEFAULT '{}',
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, protocol)
);

CREATE TABLE IF NOT EXISTS hyok_requests (
    id                   TEXT NOT NULL,
    tenant_id            TEXT NOT NULL,
    protocol             TEXT NOT NULL,
    operation            TEXT NOT NULL,
    key_id               TEXT NOT NULL,
    endpoint             TEXT NOT NULL,
    auth_mode            TEXT NOT NULL,
    auth_subject         TEXT NOT NULL DEFAULT '',
    requester_id         TEXT NOT NULL DEFAULT '',
    requester_email      TEXT NOT NULL DEFAULT '',
    policy_decision      TEXT NOT NULL DEFAULT '',
    governance_required  BOOLEAN NOT NULL DEFAULT FALSE,
    approval_request_id  TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL,
    request_json         TEXT NOT NULL DEFAULT '{}',
    response_json        TEXT NOT NULL DEFAULT '{}',
    error_message        TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at         TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_hyok_endpoints_tenant
    ON hyok_endpoints (tenant_id, protocol, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_hyok_requests_lookup
    ON hyok_requests (tenant_id, protocol, operation, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_hyok_requests_status
    ON hyok_requests (tenant_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_hyok_requests_approval
    ON hyok_requests (tenant_id, approval_request_id);

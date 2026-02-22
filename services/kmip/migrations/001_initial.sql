CREATE TABLE IF NOT EXISTS kmip_sessions (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    client_cn       TEXT NOT NULL,
    role            TEXT NOT NULL,
    remote_addr     TEXT NOT NULL,
    tls_subject     TEXT NOT NULL DEFAULT '',
    tls_issuer      TEXT NOT NULL DEFAULT '',
    connected_at    TIMESTAMP NOT NULL,
    disconnected_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS kmip_operations (
    id             TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    operation      TEXT NOT NULL,
    object_id      TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL,
    error_message  TEXT NOT NULL DEFAULT '',
    request_bytes  INTEGER NOT NULL DEFAULT 0,
    response_bytes INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS kmip_objects (
    tenant_id        TEXT NOT NULL,
    object_id        TEXT NOT NULL,
    key_id           TEXT NOT NULL,
    object_type      TEXT NOT NULL,
    name             TEXT NOT NULL,
    state            TEXT NOT NULL,
    algorithm        TEXT NOT NULL,
    attributes_json  TEXT NOT NULL DEFAULT '{}',
    created_at       TIMESTAMP NOT NULL,
    updated_at       TIMESTAMP NOT NULL,
    PRIMARY KEY (tenant_id, object_id)
);

CREATE INDEX IF NOT EXISTS idx_kmip_sessions_tenant ON kmip_sessions (tenant_id, connected_at DESC);
CREATE INDEX IF NOT EXISTS idx_kmip_ops_tenant ON kmip_operations (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_kmip_ops_request ON kmip_operations (tenant_id, request_id);
CREATE INDEX IF NOT EXISTS idx_kmip_objects_lookup ON kmip_objects (tenant_id, name, object_type, state);
CREATE INDEX IF NOT EXISTS idx_kmip_objects_key ON kmip_objects (tenant_id, key_id);


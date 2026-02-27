CREATE TABLE IF NOT EXISTS cluster_sync_nonces (
    tenant_id      TEXT NOT NULL,
    source_node_id TEXT NOT NULL DEFAULT '',
    nonce          TEXT NOT NULL,
    seen_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, source_node_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_cluster_sync_nonces_expiry
    ON cluster_sync_nonces (expires_at);

CREATE TABLE IF NOT EXISTS cluster_operation_logs (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    node_id      TEXT NOT NULL DEFAULT '',
    level        TEXT NOT NULL DEFAULT 'info',
    event_type   TEXT NOT NULL,
    message      TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cluster_operation_logs_tenant_id
    ON cluster_operation_logs (tenant_id, id DESC);

CREATE INDEX IF NOT EXISTS idx_cluster_operation_logs_tenant_event
    ON cluster_operation_logs (tenant_id, event_type, id DESC);

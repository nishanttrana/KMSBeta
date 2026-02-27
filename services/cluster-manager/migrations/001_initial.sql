CREATE TABLE IF NOT EXISTS cluster_profiles (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    components_json TEXT NOT NULL DEFAULT '[]',
    is_default      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_profiles_tenant_default
    ON cluster_profiles (tenant_id, is_default);

CREATE TABLE IF NOT EXISTS cluster_nodes (
    id                      TEXT NOT NULL,
    tenant_id               TEXT NOT NULL,
    name                    TEXT NOT NULL,
    role                    TEXT NOT NULL DEFAULT 'follower',
    endpoint                TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'unknown',
    cpu_percent             DOUBLE PRECISION NOT NULL DEFAULT 0,
    ram_gb                  DOUBLE PRECISION NOT NULL DEFAULT 0,
    enabled_components_json TEXT NOT NULL DEFAULT '[]',
    profile_id              TEXT NOT NULL,
    join_state              TEXT NOT NULL DEFAULT 'pending',
    cert_fingerprint        TEXT NOT NULL DEFAULT '',
    last_heartbeat_at       TIMESTAMPTZ,
    last_sync_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_cluster_nodes_profile
        FOREIGN KEY (tenant_id, profile_id) REFERENCES cluster_profiles (tenant_id, id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_cluster_nodes_tenant_profile
    ON cluster_nodes (tenant_id, profile_id);

CREATE TABLE IF NOT EXISTS cluster_join_tokens (
    id               TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    target_node_id   TEXT NOT NULL,
    target_node_name TEXT NOT NULL,
    endpoint         TEXT NOT NULL,
    profile_id       TEXT NOT NULL,
    secret_hash      TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    requested_by     TEXT NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ NOT NULL,
    consumed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT fk_cluster_join_profile
        FOREIGN KEY (tenant_id, profile_id) REFERENCES cluster_profiles (tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cluster_join_tokens_tenant_expiry
    ON cluster_join_tokens (tenant_id, expires_at, consumed_at);

CREATE TABLE IF NOT EXISTS cluster_sync_events (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    profile_id     TEXT NOT NULL,
    component      TEXT NOT NULL,
    entity_type    TEXT NOT NULL,
    entity_id      TEXT NOT NULL,
    operation      TEXT NOT NULL,
    payload_json   TEXT NOT NULL DEFAULT '{}',
    source_node_id TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_cluster_sync_profile
        FOREIGN KEY (tenant_id, profile_id) REFERENCES cluster_profiles (tenant_id, id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cluster_sync_events_tenant_profile_id
    ON cluster_sync_events (tenant_id, profile_id, id);

CREATE TABLE IF NOT EXISTS cluster_sync_checkpoints (
    tenant_id     TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    profile_id    TEXT NOT NULL,
    last_event_id BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, node_id, profile_id),
    CONSTRAINT fk_cluster_checkpoint_node
        FOREIGN KEY (tenant_id, node_id) REFERENCES cluster_nodes (tenant_id, id)
        ON DELETE CASCADE,
    CONSTRAINT fk_cluster_checkpoint_profile
        FOREIGN KEY (tenant_id, profile_id) REFERENCES cluster_profiles (tenant_id, id)
        ON DELETE CASCADE
);

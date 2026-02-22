CREATE TABLE IF NOT EXISTS cloud_accounts (
    tenant_id             TEXT NOT NULL,
    id                    TEXT NOT NULL,
    provider              TEXT NOT NULL,
    name                  TEXT NOT NULL,
    default_region        TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'active',
    creds_wrapped_dek     BYTEA NOT NULL,
    creds_wrapped_dek_iv  BYTEA NOT NULL,
    creds_ciphertext      BYTEA NOT NULL,
    creds_data_iv         BYTEA NOT NULL,
    created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, provider, name)
);

CREATE TABLE IF NOT EXISTS cloud_region_mappings (
    tenant_id      TEXT NOT NULL,
    provider       TEXT NOT NULL,
    vecta_region   TEXT NOT NULL,
    cloud_region   TEXT NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, provider, vecta_region)
);

CREATE TABLE IF NOT EXISTS cloud_key_bindings (
    tenant_id       TEXT NOT NULL,
    id              TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    provider        TEXT NOT NULL,
    account_id      TEXT NOT NULL,
    cloud_key_id    TEXT NOT NULL,
    cloud_key_ref   TEXT NOT NULL DEFAULT '',
    region          TEXT NOT NULL DEFAULT '',
    sync_status     TEXT NOT NULL DEFAULT 'pending',
    last_synced_at  TIMESTAMP,
    metadata_json   TEXT NOT NULL DEFAULT '{}',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS cloud_sync_jobs (
    tenant_id       TEXT NOT NULL,
    id              TEXT NOT NULL,
    provider        TEXT NOT NULL DEFAULT '',
    account_id      TEXT NOT NULL DEFAULT '',
    mode            TEXT NOT NULL DEFAULT 'full',
    status          TEXT NOT NULL,
    summary_json    TEXT NOT NULL DEFAULT '{}',
    error_message   TEXT NOT NULL DEFAULT '',
    started_at      TIMESTAMP NOT NULL,
    completed_at    TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_tenant_provider
    ON cloud_accounts (tenant_id, provider, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cloud_bindings_lookup
    ON cloud_key_bindings (tenant_id, provider, account_id, key_id);

CREATE INDEX IF NOT EXISTS idx_cloud_bindings_cloud_key
    ON cloud_key_bindings (tenant_id, provider, cloud_key_id);

CREATE INDEX IF NOT EXISTS idx_cloud_sync_jobs_tenant
    ON cloud_sync_jobs (tenant_id, status, created_at DESC);

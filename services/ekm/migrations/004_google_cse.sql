CREATE TABLE IF NOT EXISTS ekm_google_cse_configs (
    tenant_id                     TEXT NOT NULL,
    id                            TEXT NOT NULL,
    google_workspace_customer_id  TEXT NOT NULL,
    service_account_email         TEXT NOT NULL DEFAULT '',
    service_account_key_json      TEXT NOT NULL DEFAULT '',
    allowed_domains               TEXT NOT NULL DEFAULT '[]',
    kacls_endpoint                TEXT NOT NULL DEFAULT '',
    status                        TEXT NOT NULL DEFAULT 'active',
    key_count                     INTEGER NOT NULL DEFAULT 0,
    last_activity_at              TIMESTAMP,
    created_at                    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_google_cse_keys (
    tenant_id      TEXT NOT NULL,
    id             TEXT NOT NULL,
    config_id      TEXT NOT NULL,
    key_name       TEXT NOT NULL,
    vecta_key_id   TEXT NOT NULL,
    google_key_uri TEXT NOT NULL DEFAULT '',
    purpose        TEXT NOT NULL DEFAULT 'drive',
    status         TEXT NOT NULL DEFAULT 'active',
    wrap_count     INTEGER NOT NULL DEFAULT 0,
    unwrap_count   INTEGER NOT NULL DEFAULT 0,
    last_used_at   TIMESTAMP,
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ekm_google_cse_configs_tenant
    ON ekm_google_cse_configs (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_ekm_google_cse_keys_config
    ON ekm_google_cse_keys (tenant_id, config_id, status);

CREATE INDEX IF NOT EXISTS idx_ekm_google_cse_keys_uri
    ON ekm_google_cse_keys (tenant_id, google_key_uri);

CREATE INDEX IF NOT EXISTS idx_ekm_google_cse_keys_vecta
    ON ekm_google_cse_keys (tenant_id, vecta_key_id);

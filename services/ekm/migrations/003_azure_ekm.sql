CREATE TABLE IF NOT EXISTS ekm_azure_configs (
    tenant_id          TEXT NOT NULL,
    id                 TEXT NOT NULL,
    azure_tenant_id    TEXT NOT NULL,
    subscription_id    TEXT NOT NULL DEFAULT '',
    resource_group     TEXT NOT NULL DEFAULT '',
    vault_name         TEXT NOT NULL,
    vault_url          TEXT NOT NULL,
    managed_hsm_name   TEXT NOT NULL DEFAULT '',
    managed_hsm_url    TEXT NOT NULL DEFAULT '',
    client_id          TEXT NOT NULL DEFAULT '',
    client_secret      TEXT NOT NULL DEFAULT '',
    auth_mode          TEXT NOT NULL DEFAULT 'client_secret',
    status             TEXT NOT NULL DEFAULT 'active',
    key_mappings       INTEGER NOT NULL DEFAULT 0,
    last_sync_at       TIMESTAMP,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_azure_key_mappings (
    tenant_id          TEXT NOT NULL,
    id                 TEXT NOT NULL,
    config_id          TEXT NOT NULL,
    vecta_key_id       TEXT NOT NULL,
    azure_key_name     TEXT NOT NULL,
    azure_key_version  TEXT NOT NULL DEFAULT '',
    azure_key_id       TEXT NOT NULL DEFAULT '',
    purpose            TEXT NOT NULL DEFAULT 'tde',
    sync_status        TEXT NOT NULL DEFAULT 'pending',
    last_sync_at       TIMESTAMP,
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ekm_azure_configs_tenant
    ON ekm_azure_configs (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_ekm_azure_mappings_config
    ON ekm_azure_key_mappings (tenant_id, config_id, sync_status);

CREATE INDEX IF NOT EXISTS idx_ekm_azure_mappings_vecta_key
    ON ekm_azure_key_mappings (tenant_id, vecta_key_id);

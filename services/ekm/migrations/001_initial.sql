CREATE TABLE IF NOT EXISTS ekm_agents (
    tenant_id               TEXT NOT NULL,
    id                      TEXT NOT NULL,
    name                    TEXT NOT NULL,
    role                    TEXT NOT NULL DEFAULT 'ekm-agent',
    db_engine               TEXT NOT NULL DEFAULT 'mssql',
    host                    TEXT NOT NULL DEFAULT '',
    version                 TEXT NOT NULL DEFAULT '',
    status                  TEXT NOT NULL DEFAULT 'connected',
    tde_state               TEXT NOT NULL DEFAULT 'unknown',
    heartbeat_interval_sec  INTEGER NOT NULL DEFAULT 30,
    last_heartbeat_at       TIMESTAMP,
    assigned_key_id         TEXT NOT NULL DEFAULT '',
    assigned_key_version    TEXT NOT NULL DEFAULT '',
    config_version          INTEGER NOT NULL DEFAULT 1,
    config_version_ack      INTEGER NOT NULL DEFAULT 0,
    metadata_json           TEXT NOT NULL DEFAULT '{}',
    tls_client_cn           TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_tde_keys (
    tenant_id          TEXT NOT NULL,
    id                 TEXT NOT NULL,
    keycore_key_id     TEXT NOT NULL,
    name               TEXT NOT NULL,
    algorithm          TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active',
    current_version    TEXT NOT NULL DEFAULT 'v1',
    public_key_cache   TEXT NOT NULL DEFAULT '',
    public_key_format  TEXT NOT NULL DEFAULT 'opaque',
    created_by         TEXT NOT NULL DEFAULT 'ekm',
    auto_provisioned   BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_json      TEXT NOT NULL DEFAULT '{}',
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotated_at         TIMESTAMP,
    last_accessed_at   TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_databases (
    tenant_id         TEXT NOT NULL,
    id                TEXT NOT NULL,
    agent_id          TEXT NOT NULL,
    name              TEXT NOT NULL,
    engine            TEXT NOT NULL DEFAULT 'mssql',
    host              TEXT NOT NULL DEFAULT '',
    port              INTEGER NOT NULL DEFAULT 1433,
    database_name     TEXT NOT NULL DEFAULT '',
    tde_enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    tde_state         TEXT NOT NULL DEFAULT 'disabled',
    key_id            TEXT NOT NULL DEFAULT '',
    auto_provisioned  BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_json     TEXT NOT NULL DEFAULT '{}',
    last_seen_at      TIMESTAMP,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_key_access_log (
    tenant_id      TEXT NOT NULL,
    id             TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    agent_id       TEXT NOT NULL DEFAULT '',
    database_id    TEXT NOT NULL DEFAULT '',
    operation      TEXT NOT NULL,
    status         TEXT NOT NULL,
    error_message  TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ekm_agents_heartbeat
    ON ekm_agents (tenant_id, status, last_heartbeat_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_agents_key
    ON ekm_agents (tenant_id, assigned_key_id);

CREATE INDEX IF NOT EXISTS idx_ekm_tde_keys_access
    ON ekm_tde_keys (tenant_id, status, last_accessed_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_databases_agent
    ON ekm_databases (tenant_id, agent_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_databases_key
    ON ekm_databases (tenant_id, key_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_access_key
    ON ekm_key_access_log (tenant_id, key_id, created_at DESC);


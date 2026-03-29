CREATE TABLE IF NOT EXISTS tde_databases (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    engine          TEXT NOT NULL DEFAULT 'unknown',
    host            TEXT NOT NULL DEFAULT '',
    port            INTEGER NOT NULL DEFAULT 0,
    db_name         TEXT NOT NULL DEFAULT '',
    key_id          TEXT NOT NULL DEFAULT '',
    key_algorithm   TEXT NOT NULL DEFAULT 'AES-256',
    status          TEXT NOT NULL DEFAULT 'registered',
    rotation_policy TEXT NOT NULL DEFAULT 'none',
    last_rotated    TIMESTAMP,
    created_at      TIMESTAMP NOT NULL,
    updated_at      TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tde_databases_tenant ON tde_databases (tenant_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tde_databases_tenant_name ON tde_databases (tenant_id, name);

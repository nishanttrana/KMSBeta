CREATE TABLE IF NOT EXISTS secrets (
    id               TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    name             TEXT NOT NULL,
    secret_type      TEXT NOT NULL,
    description      TEXT,
    labels           TEXT NOT NULL DEFAULT '{}',
    metadata         TEXT NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'active',
    lease_ttl_seconds BIGINT NOT NULL DEFAULT 0,
    expires_at       TIMESTAMP,
    current_version  INTEGER NOT NULL DEFAULT 1,
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS secret_values (
    tenant_id     TEXT NOT NULL,
    secret_id     TEXT NOT NULL,
    version       INTEGER NOT NULL,
    wrapped_dek   BYTEA NOT NULL,
    wrapped_dek_iv BYTEA NOT NULL,
    ciphertext    BYTEA NOT NULL,
    data_iv       BYTEA NOT NULL,
    value_hash    BYTEA NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, secret_id, version)
);

CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(tenant_id, secret_type);
CREATE INDEX IF NOT EXISTS idx_secrets_expiry ON secrets(tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_secret_values_lookup ON secret_values(tenant_id, secret_id, version DESC);


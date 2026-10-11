-- Cloud BYOK (10.0.0-beta, docs/SECURITY/CLOUD_BYOK.md): KMS keys imported
-- into cloud KMSs, the custody of each piece of imported material, and the
-- step-by-step record of every operation.
CREATE TABLE IF NOT EXISTS cloud_byok_keys (
    tenant_id            TEXT NOT NULL,
    id                   TEXT NOT NULL,
    account_id           TEXT NOT NULL,
    provider             TEXT NOT NULL,
    region               TEXT NOT NULL DEFAULT '',
    key_id               TEXT NOT NULL,
    source               TEXT NOT NULL,
    origin               TEXT NOT NULL DEFAULT 'byok',
    key_spec             TEXT NOT NULL,
    usage                TEXT NOT NULL DEFAULT '',
    cloud_key_id         TEXT NOT NULL DEFAULT '',
    cloud_key_ref        TEXT NOT NULL DEFAULT '',
    alias                TEXT NOT NULL DEFAULT '',
    cloud_state          TEXT NOT NULL DEFAULT '',
    material_state       TEXT NOT NULL DEFAULT 'pending_import',
    current_material_id  TEXT NOT NULL DEFAULT '',
    settings_json        TEXT NOT NULL DEFAULT '{}',
    expires_at           TIMESTAMP,
    created_by           TEXT NOT NULL DEFAULT '',
    created_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_byok_keys_key ON cloud_byok_keys (tenant_id, key_id);

CREATE TABLE IF NOT EXISTS cloud_byok_materials (
    tenant_id            TEXT NOT NULL,
    id                   TEXT NOT NULL,
    byok_id              TEXT NOT NULL,
    kms_version          INTEGER NOT NULL,
    kcv                  TEXT NOT NULL DEFAULT '',
    cloud_material_id    TEXT NOT NULL DEFAULT '',
    state                TEXT NOT NULL,
    scheme               TEXT NOT NULL DEFAULT '',
    source               TEXT NOT NULL DEFAULT '',
    wrapping_key_sha256  TEXT NOT NULL DEFAULT '',
    imported_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at           TIMESTAMP,
    revoked_at           TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_byok_materials_key ON cloud_byok_materials (tenant_id, byok_id);

CREATE TABLE IF NOT EXISTS cloud_byok_runs (
    tenant_id      TEXT NOT NULL,
    id             TEXT NOT NULL,
    byok_id        TEXT NOT NULL,
    operation      TEXT NOT NULL,
    status         TEXT NOT NULL,
    steps_json     TEXT NOT NULL DEFAULT '[]',
    actor          TEXT NOT NULL DEFAULT '',
    error_message  TEXT NOT NULL DEFAULT '',
    started_at     TIMESTAMP NOT NULL,
    finished_at    TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_cloud_byok_runs_key ON cloud_byok_runs (tenant_id, byok_id, started_at);

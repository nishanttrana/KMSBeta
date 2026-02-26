CREATE TABLE IF NOT EXISTS governance_backup_jobs (
    id                       TEXT PRIMARY KEY,
    tenant_id                TEXT NOT NULL,
    scope                    TEXT NOT NULL,
    target_tenant_id         TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL DEFAULT 'completed',
    backup_format            TEXT NOT NULL DEFAULT 'json.gz+aes256gcm',
    encryption_algorithm     TEXT NOT NULL DEFAULT 'AES-256-GCM',
    ciphertext_sha256        TEXT NOT NULL,
    artifact_ciphertext      BYTEA NOT NULL,
    artifact_nonce           BYTEA NOT NULL,
    artifact_size_bytes      BIGINT NOT NULL DEFAULT 0,
    row_count_total          BIGINT NOT NULL DEFAULT 0,
    table_count              INTEGER NOT NULL DEFAULT 0,
    hsm_bound                BOOLEAN NOT NULL DEFAULT FALSE,
    hsm_provider_name        TEXT,
    hsm_slot_id              TEXT,
    hsm_partition_label      TEXT,
    hsm_token_label          TEXT,
    hsm_binding_fingerprint  TEXT,
    key_package_json         JSONB NOT NULL,
    created_by               TEXT,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at             TIMESTAMPTZ,
    failure_reason           TEXT
);

CREATE INDEX IF NOT EXISTS idx_governance_backup_jobs_tenant_created
    ON governance_backup_jobs (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_governance_backup_jobs_scope_target
    ON governance_backup_jobs (tenant_id, scope, target_tenant_id, created_at DESC);

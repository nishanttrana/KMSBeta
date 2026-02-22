CREATE TABLE IF NOT EXISTS token_vaults (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'vault',
    token_type TEXT NOT NULL,
    format TEXT NOT NULL,
    key_id TEXT NOT NULL,
    custom_regex TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS tokens (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    token TEXT NOT NULL,
    original_enc BYTEA NOT NULL,
    original_hash TEXT NOT NULL DEFAULT '',
    format_metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_tokens_vault ON tokens (tenant_id, vault_id);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens (tenant_id, token);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens (tenant_id, original_hash);

CREATE TABLE IF NOT EXISTS masking_policies (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL,
    field_path TEXT NOT NULL,
    mask_pattern TEXT NOT NULL,
    roles_full_json TEXT NOT NULL DEFAULT '[]',
    roles_partial_json TEXT NOT NULL DEFAULT '[]',
    roles_redacted_json TEXT NOT NULL DEFAULT '[]',
    consistent BOOLEAN NOT NULL DEFAULT TRUE,
    key_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS redaction_policies (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    patterns_json TEXT NOT NULL DEFAULT '[]',
    scope TEXT NOT NULL DEFAULT 'all',
    action TEXT NOT NULL DEFAULT 'replace_placeholder',
    placeholder TEXT NOT NULL DEFAULT '[REDACTED]',
    applies_to_json TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS fle_metadata (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    document_id TEXT NOT NULL,
    field_path TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 1,
    algorithm TEXT NOT NULL,
    iv BYTEA,
    searchable BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_fle_doc ON fle_metadata (tenant_id, document_id);

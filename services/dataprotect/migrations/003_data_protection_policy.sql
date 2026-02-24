CREATE TABLE IF NOT EXISTS data_protection_policy (
    tenant_id TEXT PRIMARY KEY,
    allowed_data_algorithms_json TEXT NOT NULL DEFAULT '["AES-GCM","AES-SIV","CHACHA20-POLY1305"]',
    require_aad_for_aead BOOLEAN NOT NULL DEFAULT FALSE,
    max_fields_per_operation INTEGER NOT NULL DEFAULT 64,
    max_document_bytes INTEGER NOT NULL DEFAULT 262144,
    allow_vaultless_tokenization BOOLEAN NOT NULL DEFAULT TRUE,
    require_token_ttl BOOLEAN NOT NULL DEFAULT FALSE,
    max_token_ttl_hours INTEGER NOT NULL DEFAULT 0,
    allow_redaction_detect_only BOOLEAN NOT NULL DEFAULT TRUE,
    allow_custom_regex_tokens BOOLEAN NOT NULL DEFAULT TRUE,
    max_token_batch INTEGER NOT NULL DEFAULT 10000,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_registered_wrapper BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS local_crypto_allowed BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS cache_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS cache_ttl_sec INTEGER NOT NULL DEFAULT 300;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS lease_max_ops INTEGER NOT NULL DEFAULT 1000;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS max_cached_keys INTEGER NOT NULL DEFAULT 16;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allowed_local_algorithms_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allowed_key_classes_for_local_export_json TEXT NOT NULL DEFAULT '["symmetric"]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS force_remote_ops_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_mtls BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_signed_nonce BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS anti_replay_window_sec INTEGER NOT NULL DEFAULT 300;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS attested_wrapper_only BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS revoke_on_policy_change BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS rekey_on_policy_change BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS field_encryption_wrappers (
    tenant_id TEXT NOT NULL,
    wrapper_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    signing_public_key_b64 TEXT NOT NULL,
    encryption_public_key_b64 TEXT NOT NULL,
    transport TEXT NOT NULL DEFAULT 'mtls+jwt',
    status TEXT NOT NULL DEFAULT 'pending',
    cert_fingerprint TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    approved_by TEXT NOT NULL DEFAULT '',
    approved_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, wrapper_id)
);

CREATE INDEX IF NOT EXISTS idx_field_wrappers_tenant_app ON field_encryption_wrappers (tenant_id, app_id);
CREATE INDEX IF NOT EXISTS idx_field_wrappers_status ON field_encryption_wrappers (tenant_id, status);

CREATE TABLE IF NOT EXISTS field_encryption_wrapper_challenges (
    tenant_id TEXT NOT NULL,
    challenge_id TEXT NOT NULL,
    wrapper_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    challenge_b64 TEXT NOT NULL,
    nonce TEXT NOT NULL,
    signing_public_key_b64 TEXT NOT NULL,
    encryption_public_key_b64 TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, challenge_id)
);

CREATE INDEX IF NOT EXISTS idx_field_wrapper_challenges_lookup ON field_encryption_wrapper_challenges (tenant_id, wrapper_id, challenge_id);

CREATE TABLE IF NOT EXISTS field_encryption_leases (
    tenant_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    wrapper_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    lease_package_json TEXT NOT NULL DEFAULT '{}',
    policy_hash TEXT NOT NULL DEFAULT '',
    revocation_counter INTEGER NOT NULL DEFAULT 0,
    max_ops INTEGER NOT NULL DEFAULT 0,
    used_ops INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoke_reason TEXT NOT NULL DEFAULT '',
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, lease_id)
);

CREATE INDEX IF NOT EXISTS idx_field_leases_wrapper ON field_encryption_leases (tenant_id, wrapper_id, revoked, expires_at);
CREATE INDEX IF NOT EXISTS idx_field_leases_key ON field_encryption_leases (tenant_id, key_id);

CREATE TABLE IF NOT EXISTS field_encryption_usage_receipts (
    tenant_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    wrapper_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    op_count INTEGER NOT NULL DEFAULT 1,
    nonce TEXT NOT NULL,
    ts TIMESTAMP NOT NULL,
    signature_b64 TEXT NOT NULL,
    payload_hash TEXT NOT NULL DEFAULT '',
    accepted BOOLEAN NOT NULL DEFAULT FALSE,
    reject_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, receipt_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_field_receipts_nonce ON field_encryption_usage_receipts (tenant_id, wrapper_id, nonce);
CREATE INDEX IF NOT EXISTS idx_field_receipts_lease ON field_encryption_usage_receipts (tenant_id, lease_id, created_at);

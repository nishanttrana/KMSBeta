ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS algorithm_profile_policy_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS required_aad_claims_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS enforce_aad_tenant_binding BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allowed_aad_environments_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS max_app_crypto_request_bytes INTEGER NOT NULL DEFAULT 1048576;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS max_app_crypto_batch_size INTEGER NOT NULL DEFAULT 256;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_symmetric_keys BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_fips_keys BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS min_key_size_bits INTEGER NOT NULL DEFAULT 0;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allowed_encrypt_field_paths_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allowed_decrypt_field_paths_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS denied_decrypt_field_paths_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS block_wildcard_field_paths BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allow_deterministic_encryption BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allow_searchable_encryption BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS allow_range_search BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS envelope_kek_allowlist_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS max_wrapped_dek_age_minutes INTEGER NOT NULL DEFAULT 0;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_rewrap_on_dek_age_exceeded BOOLEAN NOT NULL DEFAULT TRUE;

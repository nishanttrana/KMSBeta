ALTER TABLE data_protection_policy
    ADD COLUMN algorithm_profile_policy_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE data_protection_policy
    ADD COLUMN required_aad_claims_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN enforce_aad_tenant_binding BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN allowed_aad_environments_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN max_app_crypto_request_bytes INTEGER NOT NULL DEFAULT 1048576;

ALTER TABLE data_protection_policy
    ADD COLUMN max_app_crypto_batch_size INTEGER NOT NULL DEFAULT 256;

ALTER TABLE data_protection_policy
    ADD COLUMN require_symmetric_keys BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN require_fips_keys BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN min_key_size_bits INTEGER NOT NULL DEFAULT 0;

ALTER TABLE data_protection_policy
    ADD COLUMN allowed_encrypt_field_paths_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN allowed_decrypt_field_paths_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN denied_decrypt_field_paths_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN block_wildcard_field_paths BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN allow_deterministic_encryption BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN allow_searchable_encryption BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN allow_range_search BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN envelope_kek_allowlist_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN max_wrapped_dek_age_minutes INTEGER NOT NULL DEFAULT 0;

ALTER TABLE data_protection_policy
    ADD COLUMN require_rewrap_on_dek_age_exceeded BOOLEAN NOT NULL DEFAULT TRUE;

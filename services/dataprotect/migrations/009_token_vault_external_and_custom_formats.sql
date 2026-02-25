ALTER TABLE token_vaults
    ADD COLUMN IF NOT EXISTS storage_type TEXT NOT NULL DEFAULT 'internal';

ALTER TABLE token_vaults
    ADD COLUMN IF NOT EXISTS external_provider TEXT NOT NULL DEFAULT '';

ALTER TABLE token_vaults
    ADD COLUMN IF NOT EXISTS external_config_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE token_vaults
    ADD COLUMN IF NOT EXISTS external_schema_version TEXT NOT NULL DEFAULT '';

ALTER TABLE token_vaults
    ADD COLUMN IF NOT EXISTS custom_token_format TEXT NOT NULL DEFAULT '';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS custom_token_formats_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS reuse_existing_token_for_same_input BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS enforce_unique_token_per_vault BOOLEAN NOT NULL DEFAULT TRUE;

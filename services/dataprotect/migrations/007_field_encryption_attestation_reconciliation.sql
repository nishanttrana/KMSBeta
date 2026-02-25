ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS receipt_reconciliation_enabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS receipt_heartbeat_sec INTEGER NOT NULL DEFAULT 120;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS receipt_missing_grace_sec INTEGER NOT NULL DEFAULT 60;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_tpm_attestation BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS require_non_exportable_wrapper_keys BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS attestation_ak_allowlist_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE data_protection_policy
    ADD COLUMN IF NOT EXISTS attestation_allowed_pcrs_json TEXT NOT NULL DEFAULT '{}';

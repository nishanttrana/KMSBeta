-- HSM integration (docs/SECURITY/HSM_INTEGRATION.md). Replicated (keycore
-- component).
--
-- Per tenant, two switches set in the HSM tab:
--   tenant_key_enabled: new key versions have their data key encrypted by the
--     tenant's own key in its HSM (AES-256-GCM in the HSM). Existing versions
--     keep keycore's master key.
--   hsm_keys_enabled: keys may be created "in HSM": generated in and never
--     leaving the HSM; keycore sends their operations to it.
CREATE TABLE IF NOT EXISTS keycore_hsm_settings (
    tenant_id          TEXT PRIMARY KEY,
    tenant_key_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    hsm_keys_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_key_label   TEXT NOT NULL DEFAULT '',
    updated_by         TEXT NOT NULL DEFAULT '',
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- How a key version's material is protected:
--   mek          encrypted under keycore's master key (every version before this)
--   tenant_hsm   its data key encrypted by the tenant's HSM key (hsm_label)
--   hsm_resident the key is the HSM object hsm_label; keycore holds no material
ALTER TABLE key_versions ADD COLUMN IF NOT EXISTS protection TEXT NOT NULL DEFAULT 'mek';
ALTER TABLE key_versions ADD COLUMN IF NOT EXISTS hsm_label TEXT NOT NULL DEFAULT '';

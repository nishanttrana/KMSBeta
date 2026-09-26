-- The platform no longer keeps backup keys it can't protect
-- (docs/SECURITY/BACKUP_KEYS.md):
--   * software-mode packages held the backup key in plaintext next to the
--     artifact;
--   * hsm_bound "v1" packages wrapped it under a raw SHA-256 of the secret,
--     a derivation restore now refuses.
-- Both keys are removed. Those backups restore only with a key file saved
-- earlier (software), or not at all (v1 hsm_bound).
UPDATE governance_backup_jobs
SET key_package_json = (key_package_json - 'backup_key_b64' - 'wrapped_key_b64' - 'wrap_nonce_b64' - 'wrap_aad_b64')
                       || '{"key_retained": false}'::jsonb
WHERE key_package_json ? 'backup_key_b64'
   OR (key_package_json->>'mode' = 'hsm_bound' AND COALESCE(key_package_json->>'key_derivation', '') <> 'v2');

-- Stored backups are no longer re-sealed in place (they have no key to do
-- it with); captured rows are re-wrapped at creation instead.
ALTER TABLE governance_backup_jobs DROP COLUMN IF EXISTS mek_reprotected_at;

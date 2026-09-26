-- HSM-bound backup keys are now wrapped inside the tenant's HSM under its
-- tenant key (docs/SECURITY/BACKUP_KEYS.md). The secret-derived "v2" wrap
-- (HKDF of BACKUP_HSM_WRAP_SECRET) is retired like v1: its stored key is
-- removed and the backup marked not retained.
UPDATE governance_backup_jobs
SET key_package_json = (key_package_json - 'wrapped_key_b64' - 'wrap_nonce_b64' - 'wrap_aad_b64')
                       || '{"key_retained": false}'::jsonb
WHERE key_package_json->>'mode' = 'hsm_bound'
  AND COALESCE(key_package_json->>'key_wrap', '') <> 'hsm_tenant_key';

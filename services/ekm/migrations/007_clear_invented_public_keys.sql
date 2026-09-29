-- EKM TDE keys: clear the "EKM-PUBLIC-" values that buildPublicKeyFallback
-- stored as public keys. They were a hash of tenant and key ID, not key
-- material (CLAUDE.md rules 6 and 8). With the cache empty, the public key
-- endpoint asks keycore again and refuses with public_key_unavailable when
-- keycore holds none.
UPDATE ekm_tde_keys
SET public_key_cache = '', public_key_format = '', updated_at = CURRENT_TIMESTAMP
WHERE public_key_cache LIKE 'EKM-PUBLIC-%';

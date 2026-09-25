-- Working-key derivation versioning (docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md).
--
-- v1 (legacy): working key = HMAC over key identifiers (KCV / key id). Not
--              secret; kept only so data protected before this release stays
--              readable until the key is migrated.
-- v2:          working key = keycore POST /keys/{id}/service-derive (HKDF over
--              the key's secret material, bound to kms-dataprotect, tenant,
--              key, version and purpose).

-- Per-key state: legacy -> migrating -> v2. key_version is the keycore
-- version v2 derivation is pinned to (stable across key rotation).
CREATE TABLE IF NOT EXISTS dataprotect_key_kdf (
    tenant_id          TEXT NOT NULL,
    key_id             TEXT NOT NULL,
    state              TEXT NOT NULL,
    key_version        INTEGER NOT NULL DEFAULT 0,
    legacy_uses        BIGINT NOT NULL DEFAULT 0,
    last_legacy_use_at TIMESTAMP,
    updated_by         TEXT NOT NULL DEFAULT 'system',
    created_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, key_id)
);

-- Keys created before this cutoff may have legacy (v1) data and start in
-- state 'legacy'; keys created after it are v2 from birth. On a fresh install
-- the cutoff precedes every key.
CREATE TABLE IF NOT EXISTS dataprotect_kdf_meta (
    id        INTEGER PRIMARY KEY,
    v2_cutoff TIMESTAMP NOT NULL
);
INSERT INTO dataprotect_kdf_meta (id, v2_cutoff) VALUES (1, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- Every stored vault token records how its original value was protected, so
-- detokenize reads each row with the right key during and after migration.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS kdf_version TEXT NOT NULL DEFAULT 'v1';
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS kdf_key_version INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_tokens_kdf ON tokens (tenant_id, vault_id, kdf_version);

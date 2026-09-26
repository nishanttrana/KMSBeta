-- System keys (pkg/mek, docs/SECURITY/SERVICE_MASTER_KEYS.md): the keycore key
-- each platform service holds its data-protection master key under, one per
-- (service, purpose), in the internal service tenant. Every value that
-- service stores depends on it, so keycore refuses to destroy, disable,
-- delete a version of, or make exportable a key listed here. Replicated
-- (keycore component).
CREATE TABLE IF NOT EXISTS keycore_system_keys (
    client_id  TEXT NOT NULL,
    purpose    TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, purpose)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_keycore_system_keys_key ON keycore_system_keys (tenant_id, key_id);

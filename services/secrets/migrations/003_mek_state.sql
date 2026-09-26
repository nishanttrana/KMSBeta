-- Service master key (pkg/mek, docs/SECURITY/SERVICE_MASTER_KEYS.md): the
-- keycore system key and version the stored data is wrapped under (as a keyed
-- fingerprint, never the key), and the exposure register of items that were
-- stored under a public key until their material is replaced. Replicated.

CREATE TABLE IF NOT EXISTS secrets_mek_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    mek_fingerprint TEXT NOT NULL,
    rewrapped       BIGINT NOT NULL DEFAULT 0,
    unreadable      BIGINT NOT NULL DEFAULT 0,
    migrated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS secrets_mek_exposure (
    tenant_id     TEXT NOT NULL,
    item_type     TEXT NOT NULL,
    item_id       TEXT NOT NULL,
    source        TEXT NOT NULL,
    exposed_since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP,
    remediation   TEXT NOT NULL DEFAULT '',
    remediated_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, item_type, item_id)
);

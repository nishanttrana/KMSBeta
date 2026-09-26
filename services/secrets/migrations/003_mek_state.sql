-- The MEK the stored secret values are wrapped under (as a keyed fingerprint,
-- never the key) and the result of the last completed MEK migration. One row.
-- A node configured with a different MEK refuses to start instead of failing
-- every read (docs/SECURITY/SECRET_ROTATION.md).
CREATE TABLE IF NOT EXISTS secrets_mek_state (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    mek_fingerprint    TEXT NOT NULL,
    dev_mek_rewrapped  BIGINT NOT NULL DEFAULT 0,
    previous_rewrapped BIGINT NOT NULL DEFAULT 0,
    unreadable         BIGINT NOT NULL DEFAULT 0,
    migrated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

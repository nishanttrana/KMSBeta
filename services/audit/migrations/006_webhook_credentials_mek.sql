-- Webhook credentials under the audit service master key (pkg/mek,
-- docs/SECURITY/SERVICE_MASTER_KEYS.md). The signing secret and custom
-- header values are sealed together as one envelope per webhook: a random
-- DEK encrypts them, and the MEK (derived by keycore) wraps the DEK. The
-- plaintext columns are emptied when a row is sealed; headers_json keeps the
-- header names only. Rows written in plaintext by earlier releases are sealed
-- at startup and recorded in the exposure register. Replicated.

ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS has_secret BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS creds_ciphertext BYTEA;
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS creds_data_iv BYTEA;
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS creds_wrapped_dek BYTEA;
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS creds_wrapped_dek_iv BYTEA;

CREATE TABLE IF NOT EXISTS audit_mek_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    mek_fingerprint TEXT NOT NULL,
    rewrapped       BIGINT NOT NULL DEFAULT 0,
    unreadable      BIGINT NOT NULL DEFAULT 0,
    migrated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_mek_exposure (
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

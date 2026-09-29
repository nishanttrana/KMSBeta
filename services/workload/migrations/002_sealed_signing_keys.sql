-- Sealed signing keys (6.11.0-beta).
--
-- Each tenant's SPIFFE root CA private key and JWT-SVID signer private key
-- are sealed together, as one envelope per tenant, under the workload
-- service master key from keycore (pkg/mek, docs/SECURITY/SERVICE_MASTER_KEYS.md).
-- Earlier releases stored both as plaintext PEM in local_ca_key_pem and
-- jwt_signer_private_pem. Those columns stay only so the primary can seal
-- what is in them at startup (and every 15 minutes, which catches restored
-- rows), record each tenant in workload_mek_exposure, and empty them. New
-- writes leave them empty.
--
-- Plain ADD COLUMN (no IF NOT EXISTS) so the file also applies on SQLite;
-- schema_migrations applies it once.
--
-- Schema only: the tables are replicated (pkg/clustercatalog).
ALTER TABLE workload_identity_settings ADD COLUMN signing_ciphertext BYTEA;
ALTER TABLE workload_identity_settings ADD COLUMN signing_data_iv BYTEA;
ALTER TABLE workload_identity_settings ADD COLUMN signing_wrapped_dek BYTEA;
ALTER TABLE workload_identity_settings ADD COLUMN signing_wrapped_dek_iv BYTEA;

CREATE TABLE IF NOT EXISTS workload_mek_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    mek_fingerprint TEXT NOT NULL,
    rewrapped       BIGINT NOT NULL DEFAULT 0,
    unreadable      BIGINT NOT NULL DEFAULT 0,
    migrated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workload_mek_exposure (
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

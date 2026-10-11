-- Identity provider secrets under the auth service master key (pkg/mek,
-- docs/SECURITY/SERVICE_MASTER_KEYS.md), 8.2.0-beta. The LDAP and Active
-- Directory bind password, the OIDC and Entra client secret and the SAML
-- certificate were kept in secret_json in plaintext. They are now sealed
-- together as one envelope per (tenant, provider): a random DEK encrypts
-- them and the master key (derived by keycore) wraps the DEK. secret_json
-- keeps the names only, with empty values. Rows written in plaintext by
-- earlier releases are sealed once the key opens and recorded in the
-- exposure register. Replicated with auth_identity_provider_configs.

ALTER TABLE auth_identity_provider_configs ADD COLUMN IF NOT EXISTS secrets_ciphertext BYTEA;
ALTER TABLE auth_identity_provider_configs ADD COLUMN IF NOT EXISTS secrets_data_iv BYTEA;
ALTER TABLE auth_identity_provider_configs ADD COLUMN IF NOT EXISTS secrets_wrapped_dek BYTEA;
ALTER TABLE auth_identity_provider_configs ADD COLUMN IF NOT EXISTS secrets_wrapped_dek_iv BYTEA;

CREATE TABLE IF NOT EXISTS auth_mek_state (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    mek_fingerprint TEXT NOT NULL,
    rewrapped       BIGINT NOT NULL DEFAULT 0,
    unreadable      BIGINT NOT NULL DEFAULT 0,
    migrated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_mek_exposure (
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

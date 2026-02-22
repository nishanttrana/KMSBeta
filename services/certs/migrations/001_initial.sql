CREATE TABLE IF NOT EXISTS cert_cas (
    id                    TEXT NOT NULL,
    tenant_id             TEXT NOT NULL,
    name                  TEXT NOT NULL,
    parent_ca_id          TEXT,
    ca_level              TEXT NOT NULL,
    algorithm             TEXT NOT NULL,
    ca_type               TEXT NOT NULL,
    key_backend           TEXT NOT NULL,
    key_ref               TEXT NOT NULL DEFAULT '',
    cert_pem              TEXT NOT NULL,
    subject               TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL DEFAULT 'active',
    ots_current           BIGINT NOT NULL DEFAULT 0,
    ots_max               BIGINT NOT NULL DEFAULT 0,
    ots_alert_threshold   BIGINT NOT NULL DEFAULT 0,
    signer_wrapped_dek    BYTEA NOT NULL,
    signer_wrapped_dek_iv BYTEA NOT NULL,
    signer_ciphertext     BYTEA NOT NULL,
    signer_data_iv        BYTEA NOT NULL,
    created_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS cert_profiles (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    cert_type   TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    cert_class  TEXT NOT NULL,
    profile_json TEXT NOT NULL DEFAULT '{}',
    is_default  INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS cert_certificates (
    id                TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    ca_id             TEXT NOT NULL,
    serial_number     TEXT NOT NULL,
    subject_cn        TEXT NOT NULL,
    sans_json         TEXT NOT NULL DEFAULT '[]',
    cert_type         TEXT NOT NULL,
    algorithm         TEXT NOT NULL,
    profile_id        TEXT NOT NULL DEFAULT '',
    protocol          TEXT NOT NULL DEFAULT 'rest',
    cert_class        TEXT NOT NULL DEFAULT 'classical',
    cert_pem          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active',
    not_before        TIMESTAMP NOT NULL,
    not_after         TIMESTAMP NOT NULL,
    revoked_at        TIMESTAMP,
    revocation_reason TEXT NOT NULL DEFAULT '',
    key_ref           TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, serial_number)
);

CREATE TABLE IF NOT EXISTS cert_revocations (
    tenant_id      TEXT NOT NULL,
    cert_id        TEXT NOT NULL,
    ca_id          TEXT NOT NULL,
    serial_number  TEXT NOT NULL,
    reason         TEXT NOT NULL DEFAULT 'unspecified',
    revoked_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, cert_id)
);

CREATE TABLE IF NOT EXISTS cert_acme_accounts (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    email       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'valid',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS cert_acme_orders (
    id           TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    account_id   TEXT NOT NULL DEFAULT '',
    ca_id        TEXT NOT NULL,
    subject_cn   TEXT NOT NULL,
    sans_json    TEXT NOT NULL DEFAULT '[]',
    challenge_id TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    csr_pem      TEXT NOT NULL DEFAULT '',
    cert_id      TEXT,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cert_cas_parent ON cert_cas (tenant_id, parent_ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_certs_ca ON cert_certificates (tenant_id, ca_id);
CREATE INDEX IF NOT EXISTS idx_cert_certs_status ON cert_certificates (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_cert_certs_not_after ON cert_certificates (tenant_id, not_after);
CREATE INDEX IF NOT EXISTS idx_cert_revocations_ca ON cert_revocations (tenant_id, ca_id, revoked_at DESC);
CREATE INDEX IF NOT EXISTS idx_cert_acme_order_status ON cert_acme_orders (tenant_id, status);


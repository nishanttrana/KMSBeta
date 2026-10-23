-- 017: SSH certificate authorities and the certificates they issue
-- (13.49.0-beta, docs/CERTIFICATES.md "SSH certificates").
--
-- An SSH CA's private key is sealed like an X.509 CA's (the signer_*
-- columns, under the certs root wrapping key) or kept in the tenant's HSM
-- (key_backend 'hsm', key_ref the keycore key, nothing sealed here). Its
-- policy says which certificate types and principals it signs and for how
-- long. Each issued certificate is recorded so it can be listed, revoked
-- and published in the CA's KRL. Replicated (pkg/clustercatalog, certs).
CREATE TABLE IF NOT EXISTS cert_ssh_cas (
    id                        TEXT NOT NULL,
    tenant_id                 TEXT NOT NULL,
    name                      TEXT NOT NULL,
    algorithm                 TEXT NOT NULL,
    key_backend               TEXT NOT NULL,
    key_ref                   TEXT NOT NULL DEFAULT '',
    public_key                TEXT NOT NULL,
    public_key_pem            TEXT NOT NULL,
    fingerprint               TEXT NOT NULL,
    cert_types                TEXT NOT NULL DEFAULT '["user"]',
    allowed_principals        TEXT NOT NULL DEFAULT '[]',
    max_validity_seconds      BIGINT NOT NULL DEFAULT 28800,
    default_extensions        TEXT NOT NULL DEFAULT '[]',
    status                    TEXT NOT NULL DEFAULT 'active',
    signer_wrapped_dek        BYTEA NOT NULL,
    signer_wrapped_dek_iv     BYTEA NOT NULL,
    signer_ciphertext         BYTEA NOT NULL,
    signer_data_iv            BYTEA NOT NULL,
    signer_kek_version        TEXT NOT NULL DEFAULT 'legacy-v1',
    signer_fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    created_by                TEXT NOT NULL DEFAULT '',
    created_at                TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS cert_ssh_cas_name ON cert_ssh_cas (tenant_id, name);

CREATE TABLE IF NOT EXISTS cert_ssh_certificates (
    id               TEXT NOT NULL,
    tenant_id        TEXT NOT NULL,
    ca_id            TEXT NOT NULL,
    serial           TEXT NOT NULL,
    cert_type        TEXT NOT NULL,
    key_id           TEXT NOT NULL DEFAULT '',
    principals       TEXT NOT NULL DEFAULT '[]',
    key_type         TEXT NOT NULL,
    key_fingerprint  TEXT NOT NULL,
    extensions       TEXT NOT NULL DEFAULT '[]',
    critical_options TEXT NOT NULL DEFAULT '{}',
    valid_after      TIMESTAMPTZ NOT NULL,
    valid_before     TIMESTAMPTZ NOT NULL,
    issued_by        TEXT NOT NULL DEFAULT '',
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at       TIMESTAMPTZ,
    revoked_by       TEXT NOT NULL DEFAULT '',
    revoke_reason    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS cert_ssh_certificates_serial ON cert_ssh_certificates (tenant_id, ca_id, serial);
CREATE INDEX IF NOT EXISTS cert_ssh_certificates_ca ON cert_ssh_certificates (tenant_id, ca_id, issued_at);

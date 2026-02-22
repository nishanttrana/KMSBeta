CREATE TABLE IF NOT EXISTS kmip_client_profiles (
    id                        TEXT PRIMARY KEY,
    tenant_id                 TEXT NOT NULL,
    name                      TEXT NOT NULL,
    ca_id                     TEXT NOT NULL DEFAULT '',
    username_location         TEXT NOT NULL DEFAULT 'cn',
    subject_field_to_modify   TEXT NOT NULL DEFAULT 'uid',
    do_not_modify_subject_dn  INTEGER NOT NULL DEFAULT 0,
    certificate_duration_days INTEGER NOT NULL DEFAULT 365,
    role                      TEXT NOT NULL DEFAULT 'kmip-client',
    metadata_json             TEXT NOT NULL DEFAULT '{}',
    created_at                TIMESTAMP NOT NULL,
    updated_at                TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS kmip_clients (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL,
    profile_id              TEXT NOT NULL DEFAULT '',
    name                    TEXT NOT NULL,
    role                    TEXT NOT NULL,
    status                  TEXT NOT NULL DEFAULT 'active',
    enrollment_mode         TEXT NOT NULL DEFAULT 'internal',
    registration_token      TEXT NOT NULL DEFAULT '',
    cert_id                 TEXT NOT NULL DEFAULT '',
    cert_subject            TEXT NOT NULL DEFAULT '',
    cert_issuer             TEXT NOT NULL DEFAULT '',
    cert_serial             TEXT NOT NULL DEFAULT '',
    cert_fingerprint_sha256 TEXT NOT NULL,
    cert_not_before         TIMESTAMP,
    cert_not_after          TIMESTAMP,
    certificate_pem         TEXT NOT NULL DEFAULT '',
    ca_bundle_pem           TEXT NOT NULL DEFAULT '',
    metadata_json           TEXT NOT NULL DEFAULT '{}',
    created_at              TIMESTAMP NOT NULL,
    updated_at              TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_kmip_client_fingerprint ON kmip_clients (cert_fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_kmip_client_tenant ON kmip_clients (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_kmip_profile_tenant ON kmip_client_profiles (tenant_id, created_at DESC);

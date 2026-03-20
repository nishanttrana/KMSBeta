CREATE TABLE IF NOT EXISTS workload_identity_settings (
    tenant_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    trust_domain TEXT NOT NULL,
    federation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    token_exchange_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    disable_static_api_keys BOOLEAN NOT NULL DEFAULT FALSE,
    default_x509_ttl_sec INTEGER NOT NULL DEFAULT 43200,
    default_jwt_ttl_sec INTEGER NOT NULL DEFAULT 1800,
    rotation_window_sec INTEGER NOT NULL DEFAULT 1800,
    allowed_audiences_json TEXT NOT NULL DEFAULT '[]',
    local_bundle_jwks TEXT NOT NULL DEFAULT '',
    local_ca_cert_pem TEXT NOT NULL DEFAULT '',
    local_ca_key_pem TEXT NOT NULL DEFAULT '',
    jwt_signer_private_pem TEXT NOT NULL DEFAULT '',
    jwt_signer_public_pem TEXT NOT NULL DEFAULT '',
    jwt_signer_kid TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workload_identity_registrations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    spiffe_id TEXT NOT NULL,
    selectors_json TEXT NOT NULL DEFAULT '[]',
    allowed_interfaces_json TEXT NOT NULL DEFAULT '[]',
    allowed_key_ids_json TEXT NOT NULL DEFAULT '[]',
    permissions_json TEXT NOT NULL DEFAULT '[]',
    issue_x509_svid BOOLEAN NOT NULL DEFAULT FALSE,
    issue_jwt_svid BOOLEAN NOT NULL DEFAULT TRUE,
    default_ttl_sec INTEGER NOT NULL DEFAULT 1800,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_issued_at TIMESTAMP NULL,
    last_used_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, spiffe_id)
);
CREATE INDEX IF NOT EXISTS idx_workload_registrations_tenant ON workload_identity_registrations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workload_registrations_spiffe ON workload_identity_registrations(tenant_id, spiffe_id);

CREATE TABLE IF NOT EXISTS workload_identity_federation (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    trust_domain TEXT NOT NULL,
    bundle_endpoint TEXT NOT NULL DEFAULT '',
    jwks_json TEXT NOT NULL DEFAULT '',
    ca_bundle_pem TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, trust_domain)
);
CREATE INDEX IF NOT EXISTS idx_workload_federation_tenant ON workload_identity_federation(tenant_id);

CREATE TABLE IF NOT EXISTS workload_identity_issuance (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    registration_id TEXT NOT NULL,
    spiffe_id TEXT NOT NULL,
    svid_type TEXT NOT NULL,
    audiences_json TEXT NOT NULL DEFAULT '[]',
    serial_or_key_id TEXT NOT NULL DEFAULT '',
    document_hash TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NOT NULL,
    rotation_due_at TIMESTAMP NULL,
    status TEXT NOT NULL DEFAULT 'active',
    issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_workload_issuance_tenant ON workload_identity_issuance(tenant_id, issued_at DESC);

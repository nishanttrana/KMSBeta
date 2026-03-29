-- CT Log Monitor tables
CREATE TABLE IF NOT EXISTS ct_watched_domains (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    include_subdomains BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_unknown_ca BOOLEAN NOT NULL DEFAULT TRUE,
    alert_on_expiring_days INT NOT NULL DEFAULT 30,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_checked_at TIMESTAMPTZ,
    cert_count INT NOT NULL DEFAULT 0,
    alert_count INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ct_log_entries (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    subject_cn TEXT NOT NULL,
    san_json TEXT NOT NULL DEFAULT '[]',
    issuer TEXT NOT NULL,
    issuer_fingerprint TEXT NOT NULL DEFAULT '',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    serial TEXT NOT NULL DEFAULT '',
    ct_log TEXT NOT NULL DEFAULT 'argon2024',
    logged_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_known_ca BOOLEAN NOT NULL DEFAULT TRUE,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    alert_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    alert_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ct_alerts (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    entry_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    status TEXT NOT NULL DEFAULT 'open',
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cert_summary TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ct_log_entries_domain ON ct_log_entries(tenant_id, domain, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_ct_alerts_tenant_status ON ct_alerts(tenant_id, status, triggered_at DESC);

-- mTLS Mesh tables
CREATE TABLE IF NOT EXISTS mesh_services (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT 'default',
    endpoint TEXT NOT NULL,
    cert_id TEXT,
    cert_cn TEXT,
    cert_expiry TIMESTAMPTZ,
    cert_status TEXT NOT NULL DEFAULT 'missing',
    last_renewed_at TIMESTAMPTZ,
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    renew_days_before INT NOT NULL DEFAULT 30,
    trust_anchors_json TEXT NOT NULL DEFAULT '[]',
    mtls_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS mesh_certificates (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    service_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    cn TEXT NOT NULL,
    san_json TEXT NOT NULL DEFAULT '[]',
    issuer TEXT NOT NULL DEFAULT '',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    serial TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    key_algorithm TEXT NOT NULL DEFAULT 'EC-P256',
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS mesh_trust_anchors (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    subject TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS mesh_topology (
    tenant_id TEXT NOT NULL,
    from_service TEXT NOT NULL,
    to_service TEXT NOT NULL,
    mtls_verified BOOLEAN NOT NULL DEFAULT FALSE,
    last_handshake_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, from_service, to_service)
);

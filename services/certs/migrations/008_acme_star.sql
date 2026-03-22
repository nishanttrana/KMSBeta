CREATE TABLE IF NOT EXISTS cert_acme_star_subscriptions (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    account_id TEXT NOT NULL DEFAULT '',
    ca_id TEXT NOT NULL,
    profile_id TEXT,
    subject_cn TEXT NOT NULL,
    sans_json TEXT NOT NULL DEFAULT '[]',
    cert_type TEXT NOT NULL DEFAULT 'tls-server',
    cert_class TEXT NOT NULL DEFAULT 'star',
    algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256',
    validity_hours INTEGER NOT NULL DEFAULT 24,
    renew_before_minutes INTEGER NOT NULL DEFAULT 240,
    auto_renew INTEGER NOT NULL DEFAULT 1,
    allow_delegation INTEGER NOT NULL DEFAULT 1,
    delegated_subscriber TEXT,
    latest_cert_id TEXT,
    issuance_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    rollout_group TEXT,
    last_issued_at TIMESTAMP,
    next_renewal_at TIMESTAMP,
    last_error TEXT,
    created_by TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_cert_acme_star_status
    ON cert_acme_star_subscriptions (tenant_id, status, next_renewal_at);

CREATE INDEX IF NOT EXISTS idx_cert_acme_star_rollout
    ON cert_acme_star_subscriptions (tenant_id, rollout_group, next_renewal_at);

CREATE TABLE IF NOT EXISTS cert_expiry_alert_policies (
    tenant_id         TEXT NOT NULL,
    days_before       INTEGER NOT NULL DEFAULT 30,
    include_external  INTEGER NOT NULL DEFAULT 1,
    updated_by        TEXT NOT NULL DEFAULT '',
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id)
);

CREATE TABLE IF NOT EXISTS cert_expiry_alert_state (
    tenant_id      TEXT NOT NULL,
    cert_id        TEXT NOT NULL,
    last_days_left INTEGER NOT NULL,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, cert_id)
);

CREATE INDEX IF NOT EXISTS idx_cert_expiry_alert_state_tenant ON cert_expiry_alert_state (tenant_id);

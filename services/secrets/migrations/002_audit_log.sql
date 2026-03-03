CREATE TABLE IF NOT EXISTS secret_audit_log (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    secret_id   TEXT NOT NULL,
    action      TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT 'system',
    detail      TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_secret_audit_secret ON secret_audit_log(tenant_id, secret_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secret_audit_action ON secret_audit_log(tenant_id, action);

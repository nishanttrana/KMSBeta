CREATE TABLE IF NOT EXISTS dataprotect_audit_log (
    id          TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    operation   TEXT NOT NULL,
    category    TEXT NOT NULL DEFAULT 'general',
    actor       TEXT NOT NULL DEFAULT 'system',
    detail      TEXT NOT NULL DEFAULT '',
    metadata    TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_dp_audit_op ON dataprotect_audit_log(tenant_id, operation, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dp_audit_cat ON dataprotect_audit_log(tenant_id, category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dp_audit_time ON dataprotect_audit_log(tenant_id, created_at DESC);

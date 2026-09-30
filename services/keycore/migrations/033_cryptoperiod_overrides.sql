-- Tenant cryptoperiods: the operator's own period per key category, used by
-- the lifecycle scan instead of the built-in SP 800-57 default.
CREATE TABLE IF NOT EXISTS cryptoperiod_overrides (
    tenant_id TEXT NOT NULL,
    category TEXT NOT NULL,
    days INT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, category)
);

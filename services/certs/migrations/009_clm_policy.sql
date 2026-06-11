CREATE TABLE IF NOT EXISTS cert_clm_policies (
    tenant_id         TEXT NOT NULL,
    mode              TEXT NOT NULL DEFAULT 'warn',
    max_validity_days INTEGER NOT NULL DEFAULT 47,
    schedule_aware    INTEGER NOT NULL DEFAULT 1,
    renew_before_days INTEGER NOT NULL DEFAULT 15,
    updated_by        TEXT NOT NULL DEFAULT '',
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id)
);

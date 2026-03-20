CREATE TABLE IF NOT EXISTS cert_renewal_intelligence (
    tenant_id              TEXT NOT NULL,
    cert_id                TEXT NOT NULL,
    ari_id                 TEXT NOT NULL,
    ca_id                  TEXT NOT NULL DEFAULT '',
    ca_name                TEXT NOT NULL DEFAULT '',
    subject_cn             TEXT NOT NULL DEFAULT '',
    protocol               TEXT NOT NULL DEFAULT 'rest',
    not_after              TIMESTAMP NOT NULL,
    window_start           TIMESTAMP,
    window_end             TIMESTAMP,
    scheduled_renewal_at   TIMESTAMP,
    explanation_url        TEXT NOT NULL DEFAULT '',
    retry_after_seconds    INTEGER NOT NULL DEFAULT 86400,
    next_poll_at           TIMESTAMP,
    renewal_state          TEXT NOT NULL DEFAULT 'scheduled',
    risk_level             TEXT NOT NULL DEFAULT 'low',
    missed_window_at       TIMESTAMP,
    emergency_rotation_at  TIMESTAMP,
    mass_renewal_bucket    TEXT NOT NULL DEFAULT '',
    window_source          TEXT NOT NULL DEFAULT 'rfc9773_ari',
    metadata_json          TEXT NOT NULL DEFAULT '{}',
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, cert_id),
    UNIQUE (tenant_id, ari_id)
);

CREATE INDEX IF NOT EXISTS idx_cert_renewal_intelligence_schedule
    ON cert_renewal_intelligence (tenant_id, scheduled_renewal_at);

CREATE INDEX IF NOT EXISTS idx_cert_renewal_intelligence_bucket
    ON cert_renewal_intelligence (tenant_id, mass_renewal_bucket);

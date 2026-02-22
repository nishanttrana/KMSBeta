CREATE TABLE IF NOT EXISTS cert_protocol_configs (
    tenant_id   TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config_json TEXT NOT NULL DEFAULT '{}',
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, protocol)
);

CREATE INDEX IF NOT EXISTS idx_cert_protocol_configs_tenant ON cert_protocol_configs (tenant_id);

CREATE TABLE IF NOT EXISTS kmip_interop_targets (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    name                 TEXT NOT NULL,
    vendor               TEXT NOT NULL DEFAULT 'generic',
    endpoint             TEXT NOT NULL,
    server_name          TEXT NOT NULL DEFAULT '',
    expected_min_version TEXT NOT NULL DEFAULT '1.0',
    test_key_operation   INTEGER NOT NULL DEFAULT 1,
    ca_pem               TEXT NOT NULL DEFAULT '',
    client_cert_pem      TEXT NOT NULL DEFAULT '',
    client_key_pem       TEXT NOT NULL DEFAULT '',
    last_status          TEXT NOT NULL DEFAULT 'unknown',
    last_error           TEXT NOT NULL DEFAULT '',
    last_report_json     TEXT NOT NULL DEFAULT '{}',
    last_checked_at      TIMESTAMP,
    created_at           TIMESTAMP NOT NULL,
    updated_at           TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kmip_interop_target_tenant ON kmip_interop_targets (tenant_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_kmip_interop_target_tenant_name ON kmip_interop_targets (tenant_id, name);

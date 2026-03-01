CREATE TABLE IF NOT EXISTS reporting_error_telemetry (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    service TEXT NOT NULL DEFAULT '',
    component TEXT NOT NULL DEFAULT '',
    level TEXT NOT NULL DEFAULT 'error',
    message TEXT NOT NULL DEFAULT '',
    stack_trace TEXT NOT NULL DEFAULT '',
    context_json TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    release_tag TEXT NOT NULL DEFAULT '',
    build_version TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_reporting_error_telemetry_created
    ON reporting_error_telemetry (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reporting_error_telemetry_service
    ON reporting_error_telemetry (tenant_id, service, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reporting_error_telemetry_level
    ON reporting_error_telemetry (tenant_id, level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reporting_error_telemetry_fingerprint
    ON reporting_error_telemetry (tenant_id, fingerprint, created_at DESC);

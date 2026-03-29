CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'json',
    events_json TEXT NOT NULL DEFAULT '[]',
    secret TEXT NOT NULL DEFAULT '',
    headers_json TEXT NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    failure_count INT NOT NULL DEFAULT 0,
    last_delivery_at TIMESTAMPTZ,
    last_delivery_status TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    webhook_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_preview TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'success',
    http_status INT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    latency_ms INT NOT NULL DEFAULT 0,
    error TEXT NOT NULL DEFAULT '',
    attempt INT NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ops_metrics_hourly (
    tenant_id TEXT NOT NULL,
    hour TIMESTAMPTZ NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    op_type TEXT NOT NULL,
    count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    total_latency_ms BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, hour, service, op_type)
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(tenant_id, webhook_id, delivered_at DESC);
CREATE INDEX IF NOT EXISTS idx_ops_metrics_tenant_hour ON ops_metrics_hourly(tenant_id, hour DESC);

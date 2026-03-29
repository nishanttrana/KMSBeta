-- Canary / Honeypot Keys
CREATE TABLE IF NOT EXISTS canary_keys (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'AES-256-GCM',
    purpose TEXT NOT NULL DEFAULT 'detect_exfiltration',
    trip_count INT NOT NULL DEFAULT 0,
    last_tripped TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    notify_email TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_canary_keys_tenant_active
    ON canary_keys (tenant_id, active);

-- Canary Trip Events: recorded each time a canary key is accessed
CREATE TABLE IF NOT EXISTS canary_trip_events (
    id TEXT NOT NULL,
    canary_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL DEFAULT '',
    actor_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    tripped_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL DEFAULT 'critical',
    raw_request TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_canary_trip_events_canary
    ON canary_trip_events (tenant_id, canary_id, tripped_at DESC);

CREATE INDEX IF NOT EXISTS idx_canary_trip_events_recent
    ON canary_trip_events (tenant_id, tripped_at DESC);

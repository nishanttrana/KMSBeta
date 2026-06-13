-- 014: real threat detection.
--
-- key_usage_events is the per-operation usage trail that detection rules run
-- over (new actor on key, volume spike vs baseline, dormant key reactivation).
-- Rows are pruned past 30 days by the detector sweep. threat_signals holds
-- deduplicated, acknowledgeable detections surfaced by /threat/signals;
-- dedupe_key collapses repeat detections of the same condition per day.

CREATE TABLE IF NOT EXISTS key_usage_events (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    operation   TEXT NOT NULL,
    actor_id    TEXT NOT NULL DEFAULT '',
    actor_ip    TEXT NOT NULL DEFAULT '',
    interface   TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_key_usage_tenant_key_time ON key_usage_events(tenant_id, key_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_usage_tenant_time ON key_usage_events(tenant_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS threat_signals (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    signal_type     TEXT NOT NULL, -- canary_tripped, new_actor, volume_spike, dormant_key_activity
    key_id          TEXT NOT NULL DEFAULT '',
    actor_id        TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL, -- critical, high, medium, low
    description     TEXT NOT NULL,
    dedupe_key      TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT NOT NULL DEFAULT '',
    metadata        JSONB NOT NULL DEFAULT '{}',
    UNIQUE (tenant_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_threat_signals_tenant_time ON threat_signals(tenant_id, detected_at DESC);

ALTER TABLE key_usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_signals ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'key_usage_events' AND policyname = 'tenant_isolation_key_usage_events') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_usage_events ON key_usage_events USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_signals' AND policyname = 'tenant_isolation_threat_signals') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_threat_signals ON threat_signals USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

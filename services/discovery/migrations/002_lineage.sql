CREATE TABLE IF NOT EXISTS lineage_events (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT '',
    source_label TEXT NOT NULL DEFAULT '',
    dest_id TEXT NOT NULL DEFAULT '',
    dest_type TEXT NOT NULL DEFAULT '',
    dest_label TEXT NOT NULL DEFAULT '',
    actor_id TEXT NOT NULL DEFAULT '',
    actor_type TEXT NOT NULL DEFAULT '',
    service_name TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_lineage_tenant_source ON lineage_events(tenant_id, source_id);
CREATE INDEX IF NOT EXISTS idx_lineage_tenant_dest ON lineage_events(tenant_id, dest_id);
CREATE INDEX IF NOT EXISTS idx_lineage_occurred ON lineage_events(tenant_id, occurred_at DESC);

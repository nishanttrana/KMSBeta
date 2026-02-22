CREATE TABLE IF NOT EXISTS discovery_scans (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    trigger TEXT NOT NULL DEFAULT 'manual',
    stats_json TEXT NOT NULL DEFAULT '{}',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_discovery_scans_created ON discovery_scans (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS discovery_assets (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    scan_id TEXT NOT NULL DEFAULT '',
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'UNKNOWN',
    strength_bits INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    classification TEXT NOT NULL DEFAULT 'unknown',
    pqc_ready BOOLEAN NOT NULL DEFAULT FALSE,
    qsl_score REAL NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_discovery_assets_source ON discovery_assets (tenant_id, source);
CREATE INDEX IF NOT EXISTS idx_discovery_assets_type ON discovery_assets (tenant_id, asset_type);
CREATE INDEX IF NOT EXISTS idx_discovery_assets_class ON discovery_assets (tenant_id, classification);
CREATE INDEX IF NOT EXISTS idx_discovery_assets_updated ON discovery_assets (tenant_id, updated_at DESC);

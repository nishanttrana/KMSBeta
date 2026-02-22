CREATE TABLE IF NOT EXISTS sbom_snapshots (
    id TEXT PRIMARY KEY,
    appliance_id TEXT NOT NULL DEFAULT 'vecta-kms',
    format TEXT NOT NULL DEFAULT 'cyclonedx',
    spec_version TEXT NOT NULL DEFAULT '1.6',
    source_hash TEXT NOT NULL DEFAULT '',
    summary_json TEXT NOT NULL DEFAULT '{}',
    document_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sbom_snapshots_created_at
    ON sbom_snapshots (created_at DESC);

CREATE TABLE IF NOT EXISTS cbom_snapshots (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'cyclonedx-crypto',
    spec_version TEXT NOT NULL DEFAULT '1.6',
    source_hash TEXT NOT NULL DEFAULT '',
    summary_json TEXT NOT NULL DEFAULT '{}',
    document_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_cbom_snapshots_tenant_created_at
    ON cbom_snapshots (tenant_id, created_at DESC);

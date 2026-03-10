CREATE TABLE IF NOT EXISTS sbom_manual_advisories (
    id TEXT PRIMARY KEY,
    component TEXT NOT NULL,
    ecosystem TEXT NOT NULL DEFAULT '',
    introduced_version TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    summary TEXT NOT NULL DEFAULT '',
    reference TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sbom_manual_advisories_component
    ON sbom_manual_advisories (component, ecosystem);

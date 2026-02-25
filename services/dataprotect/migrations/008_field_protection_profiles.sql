CREATE TABLE IF NOT EXISTS field_protection_profiles (
    tenant_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    name TEXT NOT NULL,
    app_id TEXT NOT NULL DEFAULT '*',
    wrapper_id TEXT NOT NULL DEFAULT '*',
    status TEXT NOT NULL DEFAULT 'active',
    priority INTEGER NOT NULL DEFAULT 100,
    cache_ttl_sec INTEGER NOT NULL DEFAULT 300,
    policy_hash TEXT NOT NULL DEFAULT '',
    rules_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    updated_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_field_protection_profiles_lookup
    ON field_protection_profiles (tenant_id, status, app_id, wrapper_id, priority);

CREATE INDEX IF NOT EXISTS idx_field_protection_profiles_app
    ON field_protection_profiles (tenant_id, app_id);

CREATE INDEX IF NOT EXISTS idx_field_protection_profiles_wrapper
    ON field_protection_profiles (tenant_id, wrapper_id);

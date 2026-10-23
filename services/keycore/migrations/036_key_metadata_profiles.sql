-- 036: key metadata profiles (13.50.0-beta, docs/KEYS.md "Metadata
-- profiles"). A profile says which metadata a key must carry: an owner, a
-- description, labels (required, from a list, matching a pattern, or with a
-- default) and tags. Keys of the profile's purposes (every key when none)
-- are checked when created, imported or updated. rules is the JSON of
-- MetadataProfileRules. Replicated (pkg/clustercatalog, keycore).
CREATE TABLE IF NOT EXISTS key_metadata_profiles (
    tenant_id   TEXT NOT NULL,
    id          TEXT NOT NULL,
    name        TEXT NOT NULL,
    purposes    TEXT NOT NULL DEFAULT '[]',
    rules       TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'active',
    created_by  TEXT NOT NULL DEFAULT '',
    updated_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS key_metadata_profiles_name ON key_metadata_profiles (tenant_id, name);

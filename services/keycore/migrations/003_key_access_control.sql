BEGIN;

CREATE TABLE IF NOT EXISTS key_access_groups (
    tenant_id    TEXT NOT NULL,
    id           TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT,
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS key_access_group_members (
    tenant_id   TEXT NOT NULL,
    group_id    TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, group_id, user_id)
);

CREATE TABLE IF NOT EXISTS key_access_grants (
    tenant_id     TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    subject_type  TEXT NOT NULL,
    subject_id    TEXT NOT NULL,
    operations    JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, key_id, subject_type, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_key_access_groups_name ON key_access_groups(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_key_access_group_members_user ON key_access_group_members(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_key_access_grants_key ON key_access_grants(tenant_id, key_id);
CREATE INDEX IF NOT EXISTS idx_key_access_grants_subject ON key_access_grants(tenant_id, subject_type, subject_id);

ALTER TABLE key_access_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_access_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_access_grants ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_access_groups') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_access_groups ON key_access_groups USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_access_group_members') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_access_group_members ON key_access_group_members USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_access_grants') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_access_grants ON key_access_grants USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;

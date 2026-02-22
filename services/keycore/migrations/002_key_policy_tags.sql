BEGIN;

ALTER TABLE keys
    ADD COLUMN IF NOT EXISTS export_allowed BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE keys
    ADD COLUMN IF NOT EXISTS tags JSONB;

UPDATE keys
SET tags = '[]'::jsonb
WHERE tags IS NULL;

CREATE TABLE IF NOT EXISTS key_tags (
    tenant_id   TEXT NOT NULL,
    name        TEXT NOT NULL,
    color       TEXT NOT NULL,
    is_system   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_key_tags_tenant ON key_tags(tenant_id);

ALTER TABLE key_tags ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_tags') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_tags ON key_tags USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;

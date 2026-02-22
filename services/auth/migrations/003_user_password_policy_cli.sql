BEGIN;

CREATE TABLE IF NOT EXISTS auth_password_policies (
    tenant_id               TEXT PRIMARY KEY REFERENCES auth_tenants(id) ON DELETE CASCADE,
    min_length              INTEGER NOT NULL DEFAULT 12,
    max_length              INTEGER NOT NULL DEFAULT 128,
    require_upper           BOOLEAN NOT NULL DEFAULT TRUE,
    require_lower           BOOLEAN NOT NULL DEFAULT TRUE,
    require_digit           BOOLEAN NOT NULL DEFAULT TRUE,
    require_special         BOOLEAN NOT NULL DEFAULT TRUE,
    require_no_whitespace   BOOLEAN NOT NULL DEFAULT TRUE,
    deny_username           BOOLEAN NOT NULL DEFAULT TRUE,
    deny_email_local_part   BOOLEAN NOT NULL DEFAULT TRUE,
    min_unique_chars        INTEGER NOT NULL DEFAULT 6,
    updated_by              TEXT NOT NULL DEFAULT 'system',
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE auth_password_policies ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_password_policies') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_password_policies ON auth_password_policies USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;

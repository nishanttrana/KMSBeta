BEGIN;

CREATE TABLE IF NOT EXISTS auth_security_policies (
    tenant_id             TEXT PRIMARY KEY REFERENCES auth_tenants(id) ON DELETE CASCADE,
    max_failed_attempts   INTEGER NOT NULL DEFAULT 5,
    lockout_minutes       INTEGER NOT NULL DEFAULT 15,
    idle_timeout_minutes  INTEGER NOT NULL DEFAULT 15,
    updated_by            TEXT NOT NULL DEFAULT 'system',
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE auth_security_policies ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_security_policies') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_security_policies ON auth_security_policies USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;


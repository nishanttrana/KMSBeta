BEGIN;

CREATE TABLE IF NOT EXISTS auth_tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_tenant_roles (
    tenant_id   TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    role_name   TEXT NOT NULL,
    permissions JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, role_name)
);

CREATE TABLE IF NOT EXISTS auth_users (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    email       TEXT NOT NULL,
    pwd_hash    BYTEA NOT NULL,
    totp_secret TEXT,
    role        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active',
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, username),
    UNIQUE (tenant_id, email)
);

CREATE TABLE IF NOT EXISTS auth_client_registrations (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    client_name     TEXT NOT NULL,
    client_type     TEXT NOT NULL,
    description     TEXT,
    contact_email   TEXT NOT NULL,
    requested_role  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    api_key_hash    BYTEA,
    api_key_prefix  TEXT,
    approved_by     JSONB,
    approval_id     TEXT,
    ip_whitelist    JSONB,
    rate_limit      INTEGER NOT NULL DEFAULT 1000,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    last_used       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_api_keys (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    user_id     TEXT REFERENCES auth_users(id) ON DELETE SET NULL,
    client_id   TEXT REFERENCES auth_client_registrations(id) ON DELETE SET NULL,
    key_hash    BYTEA NOT NULL,
    name        TEXT NOT NULL,
    permissions JSONB NOT NULL,
    expires_at  TIMESTAMPTZ,
    last_used   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL,
    ip_address  INET,
    user_agent  TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_users_tenant ON auth_users (tenant_id);
CREATE INDEX IF NOT EXISTS idx_auth_clients_tenant ON auth_client_registrations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_tenant ON auth_api_keys (tenant_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_tenant ON auth_sessions (tenant_id);

ALTER TABLE auth_tenant_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_client_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_tenant_roles') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_tenant_roles ON auth_tenant_roles USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_users') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_users ON auth_users USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_client_registrations') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_client_registrations ON auth_client_registrations USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_api_keys') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_api_keys ON auth_api_keys USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_sessions') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_auth_sessions ON auth_sessions USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;

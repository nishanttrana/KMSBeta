BEGIN;

ALTER TABLE key_access_grants
    ADD COLUMN IF NOT EXISTS not_before TIMESTAMPTZ;
ALTER TABLE key_access_grants
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE key_access_grants
    ADD COLUMN IF NOT EXISTS justification TEXT;
ALTER TABLE key_access_grants
    ADD COLUMN IF NOT EXISTS ticket_id TEXT;

CREATE INDEX IF NOT EXISTS idx_key_access_grants_window
    ON key_access_grants (tenant_id, key_id, not_before, expires_at);

CREATE TABLE IF NOT EXISTS key_access_policy_settings (
    tenant_id                            TEXT PRIMARY KEY,
    deny_by_default                      BOOLEAN NOT NULL DEFAULT FALSE,
    require_approval_for_policy_change   BOOLEAN NOT NULL DEFAULT FALSE,
    grant_default_ttl_minutes            INTEGER NOT NULL DEFAULT 0,
    grant_max_ttl_minutes                INTEGER NOT NULL DEFAULT 0,
    enforce_signed_requests              BOOLEAN NOT NULL DEFAULT FALSE,
    replay_window_seconds                INTEGER NOT NULL DEFAULT 300,
    nonce_ttl_seconds                    INTEGER NOT NULL DEFAULT 900,
    require_interface_policies           BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by                           TEXT,
    updated_at                           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS key_interface_subject_policies (
    tenant_id        TEXT NOT NULL,
    id               TEXT NOT NULL,
    interface_name   TEXT NOT NULL,
    subject_type     TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    operations       JSONB NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_by       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_key_if_subject_lookup
    ON key_interface_subject_policies (tenant_id, interface_name, subject_type, subject_id);

CREATE TABLE IF NOT EXISTS key_interface_ports (
    tenant_id        TEXT NOT NULL,
    interface_name   TEXT NOT NULL,
    bind_address     TEXT NOT NULL DEFAULT '0.0.0.0',
    port             INTEGER NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    description      TEXT,
    updated_by       TEXT,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, interface_name)
);

CREATE TABLE IF NOT EXISTS key_request_nonce_cache (
    tenant_id        TEXT NOT NULL,
    nonce            TEXT NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_key_request_nonce_expiry
    ON key_request_nonce_cache (tenant_id, expires_at);

ALTER TABLE key_access_policy_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_interface_subject_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_interface_ports ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_request_nonce_cache ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_access_policy_settings') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_access_policy_settings ON key_access_policy_settings USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_interface_subject_policies') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_interface_subject_policies ON key_interface_subject_policies USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_interface_ports') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_interface_ports ON key_interface_ports USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_request_nonce_cache') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_request_nonce_cache ON key_request_nonce_cache USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;


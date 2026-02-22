BEGIN;

CREATE TABLE IF NOT EXISTS keys (
    id                  TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    name                TEXT NOT NULL,
    algorithm           TEXT NOT NULL,
    key_type            TEXT NOT NULL,
    purpose             TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pre-active',
    current_version     INTEGER NOT NULL DEFAULT 1,
    kcv                 BYTEA,
    kcv_algorithm       TEXT,
    iv_mode             TEXT DEFAULT 'internal',
    owner               TEXT NOT NULL,
    cloud               TEXT,
    region              TEXT,
    compliance          JSONB,
    labels              JSONB,
    activation_date     TIMESTAMPTZ,
    expiry_date         TIMESTAMPTZ,
    destroy_date        TIMESTAMPTZ,
    pqc_ready           BOOLEAN DEFAULT FALSE,
    qsl_score           INTEGER DEFAULT 0,
    fips_compliant      BOOLEAN DEFAULT TRUE,
    fips_mode_at_creation TEXT,
    hsm_mode            TEXT NOT NULL DEFAULT 'inherit',
    hsm_key_label       TEXT,
    ops_total           BIGINT DEFAULT 0,
    ops_encrypt         BIGINT DEFAULT 0,
    ops_decrypt         BIGINT DEFAULT 0,
    ops_sign            BIGINT DEFAULT 0,
    ops_limit           BIGINT DEFAULT 0,
    ops_limit_window    TEXT,
    ops_last_reset      TIMESTAMPTZ,
    approval_required   BOOLEAN DEFAULT FALSE,
    approval_policy_id  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by          TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id)
) PARTITION BY HASH (tenant_id);

DO $$
DECLARE i INTEGER;
DECLARE part_name TEXT;
BEGIN
    FOR i IN 0..63 LOOP
        part_name := 'keys_p' || lpad(i::text, 2, '0');
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF keys FOR VALUES WITH (MODULUS 64, REMAINDER %s)',
            part_name, i
        );
    END LOOP;
END $$;

CREATE TABLE IF NOT EXISTS key_versions (
    id                  TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    version             INTEGER NOT NULL,
    encrypted_material  BYTEA NOT NULL,
    material_iv         BYTEA NOT NULL,
    wrapped_dek         BYTEA NOT NULL,
    public_key          BYTEA,
    kcv                 BYTEA,
    rotated_from        INTEGER,
    rotation_reason     TEXT,
    status              TEXT NOT NULL DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS key_iv_log (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    key_id          TEXT NOT NULL,
    key_version     INTEGER NOT NULL,
    iv              BYTEA NOT NULL,
    operation       TEXT NOT NULL,
    reference_id    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_iv_log_key ON key_iv_log(tenant_id, key_id, key_version);
CREATE INDEX IF NOT EXISTS idx_iv_log_ref ON key_iv_log(tenant_id, reference_id) WHERE reference_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_keys_name ON keys(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_keys_owner ON keys(tenant_id, owner);
CREATE INDEX IF NOT EXISTS idx_keys_cloud ON keys(tenant_id, cloud);
CREATE INDEX IF NOT EXISTS idx_keys_purpose ON keys(tenant_id, purpose);
CREATE INDEX IF NOT EXISTS idx_keys_algorithm ON keys(tenant_id, algorithm);
CREATE INDEX IF NOT EXISTS idx_keys_labels ON keys USING GIN(labels);
CREATE INDEX IF NOT EXISTS idx_keys_compliance ON keys USING GIN(compliance);
CREATE INDEX IF NOT EXISTS idx_keys_expiry ON keys(tenant_id, expiry_date) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_key_versions_key ON key_versions(tenant_id, key_id);

ALTER TABLE keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_iv_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_keys') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_keys ON keys USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_versions') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_versions ON key_versions USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_iv_log') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_iv_log ON key_iv_log USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;


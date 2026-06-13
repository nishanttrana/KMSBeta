-- 015: external credential -> key bindings.
--
-- Records that an external credential (an AWS/GCP key, a DB password, etc.)
-- is protected/wrapped by a given KMS key, keyed by a non-reversible
-- fingerprint of the credential (SHA-256 hex of the raw value). The leak
-- scanner computes the same fingerprint when it finds a secret, so the
-- unified Threat & Exposure console can resolve a leaked credential to the
-- KMS key it protects and correlate the leak with anomalous usage of that
-- key. No plaintext credential material is ever stored here.

CREATE TABLE IF NOT EXISTS external_credential_bindings (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,          -- sha256 hex of the credential value
    credential_type TEXT NOT NULL DEFAULT '', -- aws_secret_access_key, db_password, ...
    key_id          TEXT NOT NULL,
    label           TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_cred_bindings_key ON external_credential_bindings(tenant_id, key_id);

ALTER TABLE external_credential_bindings ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'external_credential_bindings' AND policyname = 'tenant_isolation_external_credential_bindings') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_external_credential_bindings ON external_credential_bindings USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

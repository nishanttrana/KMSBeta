BEGIN;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS auth_mode TEXT NOT NULL DEFAULT 'api_key';

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS replay_protection_enabled BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS mtls_cert_fingerprint TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS mtls_subject_dn TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS mtls_uri_san TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS http_signature_key_id TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS http_signature_public_key_pem TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS http_signature_algorithm TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS verified_request_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS replay_violation_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS signature_failure_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS unsigned_reject_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS last_verified_request_at TIMESTAMPTZ;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS last_replay_violation_at TIMESTAMPTZ;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS last_signature_failure_at TIMESTAMPTZ;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS last_unsigned_reject_at TIMESTAMPTZ;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS last_auth_mode_used TEXT;

UPDATE auth_client_registrations
SET auth_mode = 'api_key'
WHERE auth_mode IS NULL OR btrim(auth_mode) = '';

CREATE TABLE IF NOT EXISTS auth_request_nonce_cache (
  tenant_id   TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
  nonce       TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_auth_request_nonce_expiry
  ON auth_request_nonce_cache (tenant_id, expires_at);

ALTER TABLE auth_request_nonce_cache ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_auth_request_nonce_cache') THEN
    EXECUTE 'CREATE POLICY tenant_isolation_auth_request_nonce_cache ON auth_request_nonce_cache USING (tenant_id = current_setting(''app.tenant_id'', true))';
  END IF;
END $$;

COMMIT;

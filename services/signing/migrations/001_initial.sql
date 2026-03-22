CREATE TABLE IF NOT EXISTS signing_settings (
  tenant_id TEXT PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  default_profile_id TEXT NOT NULL DEFAULT '',
  require_transparency BOOLEAN NOT NULL DEFAULT TRUE,
  allowed_identity_modes_json JSONB NOT NULL DEFAULT '["oidc","workload"]'::jsonb,
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS signing_profiles (
  id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  artifact_type TEXT NOT NULL DEFAULT 'blob',
  key_id TEXT NOT NULL,
  signing_algorithm TEXT NOT NULL DEFAULT 'ecdsa-sha384',
  identity_mode TEXT NOT NULL DEFAULT 'oidc',
  allowed_workload_patterns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_oidc_issuers_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_subject_patterns_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_repositories_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  transparency_required BOOLEAN NOT NULL DEFAULT TRUE,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  description TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_signing_profiles_tenant_enabled ON signing_profiles (tenant_id, enabled);

CREATE TABLE IF NOT EXISTS signing_records (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL,
  artifact_name TEXT NOT NULL DEFAULT '',
  digest_sha256 TEXT NOT NULL,
  signature_b64 TEXT NOT NULL,
  key_id TEXT NOT NULL,
  signing_algorithm TEXT NOT NULL,
  identity_mode TEXT NOT NULL,
  oidc_issuer TEXT NOT NULL DEFAULT '',
  oidc_subject TEXT NOT NULL DEFAULT '',
  workload_identity TEXT NOT NULL DEFAULT '',
  repository TEXT NOT NULL DEFAULT '',
  commit_sha TEXT NOT NULL DEFAULT '',
  oci_reference TEXT NOT NULL DEFAULT '',
  transparency_entry_id TEXT NOT NULL DEFAULT '',
  transparency_hash TEXT NOT NULL DEFAULT '',
  transparency_index INTEGER NOT NULL DEFAULT 0,
  verification_status TEXT NOT NULL DEFAULT 'logged',
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_signing_records_tenant_created ON signing_records (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_signing_records_tenant_profile ON signing_records (tenant_id, profile_id, created_at DESC);

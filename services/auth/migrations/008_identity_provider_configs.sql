BEGIN;

CREATE TABLE IF NOT EXISTS auth_identity_provider_configs (
    tenant_id    TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    config_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by   TEXT NOT NULL DEFAULT 'system',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_auth_identity_provider_configs_tenant_enabled
  ON auth_identity_provider_configs (tenant_id, enabled);

COMMIT;

BEGIN;

CREATE TABLE IF NOT EXISTS auth_hsm_provider_configs (
    tenant_id           TEXT PRIMARY KEY REFERENCES auth_tenants(id) ON DELETE CASCADE,
    provider_name       TEXT NOT NULL DEFAULT 'customer-hsm',
    integration_service TEXT NOT NULL DEFAULT 'hsm-integration',
    library_path        TEXT NOT NULL DEFAULT '',
    slot_id             TEXT NOT NULL DEFAULT '',
    partition_label     TEXT NOT NULL DEFAULT '',
    token_label         TEXT NOT NULL DEFAULT '',
    pin_env_var         TEXT NOT NULL DEFAULT 'HSM_PIN',
    read_only           BOOLEAN NOT NULL DEFAULT FALSE,
    enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by          TEXT NOT NULL DEFAULT 'system',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_hsm_provider_configs_enabled
  ON auth_hsm_provider_configs (tenant_id, enabled);

COMMIT;

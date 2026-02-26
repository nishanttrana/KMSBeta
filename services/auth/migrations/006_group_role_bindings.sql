BEGIN;

CREATE TABLE IF NOT EXISTS auth_group_role_bindings (
  tenant_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  role_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_group_role_bindings_tenant_role
  ON auth_group_role_bindings (tenant_id, role_name);

COMMIT;

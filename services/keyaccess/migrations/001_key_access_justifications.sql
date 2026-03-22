CREATE TABLE IF NOT EXISTS key_access_settings (
  tenant_id TEXT PRIMARY KEY,
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  mode TEXT NOT NULL DEFAULT 'enforce',
  default_action TEXT NOT NULL DEFAULT 'deny',
  require_justification_code BOOLEAN NOT NULL DEFAULT TRUE,
  require_justification_text BOOLEAN NOT NULL DEFAULT FALSE,
  approval_policy_id TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_access_rules (
  id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  code TEXT NOT NULL,
  label TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL DEFAULT 'deny',
  services_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  operations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  require_text BOOLEAN NOT NULL DEFAULT FALSE,
  approval_policy_id TEXT NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, code)
);

CREATE INDEX IF NOT EXISTS idx_key_access_rules_tenant_enabled ON key_access_rules (tenant_id, enabled);

CREATE TABLE IF NOT EXISTS key_access_decisions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  connector TEXT NOT NULL DEFAULT '',
  operation TEXT NOT NULL,
  key_id TEXT NOT NULL DEFAULT '',
  resource_id TEXT NOT NULL DEFAULT '',
  target_type TEXT NOT NULL DEFAULT '',
  request_id TEXT NOT NULL DEFAULT '',
  requester_id TEXT NOT NULL DEFAULT '',
  requester_email TEXT NOT NULL DEFAULT '',
  requester_ip TEXT NOT NULL DEFAULT '',
  justification_code TEXT NOT NULL DEFAULT '',
  justification_text TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL,
  approval_required BOOLEAN NOT NULL DEFAULT FALSE,
  approval_request_id TEXT NOT NULL DEFAULT '',
  matched_rule_id TEXT NOT NULL DEFAULT '',
  matched_code TEXT NOT NULL DEFAULT '',
  policy_mode TEXT NOT NULL DEFAULT 'enforce',
  reason TEXT NOT NULL DEFAULT '',
  bypass_detected BOOLEAN NOT NULL DEFAULT FALSE,
  metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_key_access_decisions_tenant_created ON key_access_decisions (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_access_decisions_tenant_service ON key_access_decisions (tenant_id, service_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_access_decisions_tenant_decision ON key_access_decisions (tenant_id, decision, created_at DESC);

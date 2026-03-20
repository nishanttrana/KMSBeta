CREATE TABLE IF NOT EXISTS autokey_settings (
    tenant_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mode TEXT NOT NULL DEFAULT 'enforce',
    require_approval BOOLEAN NOT NULL DEFAULT TRUE,
    require_justification BOOLEAN NOT NULL DEFAULT TRUE,
    allow_template_override BOOLEAN NOT NULL DEFAULT TRUE,
    default_policy_id TEXT NOT NULL DEFAULT '',
    default_rotation_days INTEGER NOT NULL DEFAULT 90,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS autokey_templates (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    service_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    handle_name_pattern TEXT NOT NULL,
    key_name_pattern TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_type TEXT NOT NULL,
    purpose TEXT NOT NULL,
    export_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    iv_mode TEXT NOT NULL DEFAULT 'internal',
    tags_json TEXT NOT NULL DEFAULT '[]',
    labels_json TEXT NOT NULL DEFAULT '{}',
    ops_limit BIGINT NOT NULL DEFAULT 0,
    ops_limit_window TEXT NOT NULL DEFAULT '',
    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    approval_policy_id TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_autokey_templates_service
    ON autokey_templates (tenant_id, service_name, resource_type, enabled);

CREATE TABLE IF NOT EXISTS autokey_service_policies (
    tenant_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    default_template_id TEXT NOT NULL DEFAULT '',
    algorithm TEXT NOT NULL DEFAULT '',
    key_type TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    export_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    iv_mode TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    labels_json TEXT NOT NULL DEFAULT '{}',
    ops_limit BIGINT NOT NULL DEFAULT 0,
    ops_limit_window TEXT NOT NULL DEFAULT '',
    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    approval_policy_id TEXT NOT NULL DEFAULT '',
    enforce_policy BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, service_name)
);

CREATE TABLE IF NOT EXISTS autokey_requests (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    template_id TEXT NOT NULL DEFAULT '',
    requester_id TEXT NOT NULL DEFAULT '',
    requester_email TEXT NOT NULL DEFAULT '',
    requester_ip TEXT NOT NULL DEFAULT '',
    justification TEXT NOT NULL DEFAULT '',
    requested_algorithm TEXT NOT NULL DEFAULT '',
    requested_key_type TEXT NOT NULL DEFAULT '',
    requested_purpose TEXT NOT NULL DEFAULT '',
    handle_name TEXT NOT NULL DEFAULT '',
    key_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    approval_required BOOLEAN NOT NULL DEFAULT FALSE,
    governance_request_id TEXT NOT NULL DEFAULT '',
    handle_id TEXT NOT NULL DEFAULT '',
    key_id TEXT NOT NULL DEFAULT '',
    policy_matched BOOLEAN NOT NULL DEFAULT TRUE,
    policy_mismatch_reason TEXT NOT NULL DEFAULT '',
    resolved_spec_json TEXT NOT NULL DEFAULT '{}',
    failure_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    fulfilled_at TIMESTAMP NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_autokey_requests_status
    ON autokey_requests (tenant_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS autokey_handles (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    service_name TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_ref TEXT NOT NULL,
    handle_name TEXT NOT NULL,
    key_id TEXT NOT NULL,
    template_id TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    managed BOOLEAN NOT NULL DEFAULT TRUE,
    policy_matched BOOLEAN NOT NULL DEFAULT TRUE,
    spec_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, service_name, resource_type, resource_ref)
);

CREATE INDEX IF NOT EXISTS idx_autokey_handles_service
    ON autokey_handles (tenant_id, service_name, created_at DESC);

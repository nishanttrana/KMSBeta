CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_tenant_id_id
    ON auth_users (tenant_id, id);

CREATE TABLE IF NOT EXISTS auth_scim_settings (
    tenant_id TEXT PRIMARY KEY REFERENCES auth_tenants(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    token_hash BYTEA,
    token_prefix TEXT NOT NULL DEFAULT '',
    default_role TEXT NOT NULL DEFAULT 'readonly',
    default_status TEXT NOT NULL DEFAULT 'active',
    default_must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    deprovision_mode TEXT NOT NULL DEFAULT 'disable',
    group_role_mappings_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by TEXT NOT NULL DEFAULT 'system',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_scim_user_links (
    tenant_id TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    external_id TEXT,
    display_name TEXT NOT NULL DEFAULT '',
    given_name TEXT NOT NULL DEFAULT '',
    family_name TEXT NOT NULL DEFAULT '',
    scim_managed BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT NOT NULL DEFAULT 'scim',
    last_synced_at TIMESTAMPTZ,
    deprovisioned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_scim_user_links_external_id
    ON auth_scim_user_links (tenant_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS auth_scim_groups (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    external_id TEXT,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    scim_managed BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_scim_groups_external_id
    ON auth_scim_groups (tenant_id, external_id)
    WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS auth_scim_group_members (
    tenant_id TEXT NOT NULL REFERENCES auth_tenants(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, group_id, user_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES auth_scim_groups(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES auth_users(tenant_id, id) ON DELETE CASCADE
);

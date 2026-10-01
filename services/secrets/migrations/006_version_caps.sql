-- 7.31.0-beta. A version cap for one secret or one folder, overriding the
-- tenant's (secret_vault_settings.max_versions). path has the same form as
-- an access rule's: /team/db or /team/*. Replicated.
CREATE TABLE IF NOT EXISTS secret_version_caps (
    id           TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    path         TEXT NOT NULL,
    max_versions INTEGER NOT NULL,
    updated_by   TEXT NOT NULL DEFAULT '',
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, path)
);

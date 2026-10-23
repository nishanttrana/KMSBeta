-- 014: a REST client's granted role (13.53.0-beta, docs/CI_CD_AUTOMATION.md
-- "A role for a client"). Without a row, a client's tokens hold kms.read and
-- kms.write (secrets and signing only). With one, they hold the role's
-- permissions as they are when each token is issued, so a role change
-- reaches every client that has it. requested_role on the registration is
-- what the requester asked for; it grants nothing. Replicated
-- (pkg/clustercatalog, auth).
CREATE TABLE IF NOT EXISTS auth_client_roles (
    tenant_id  TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    role_name  TEXT NOT NULL,
    granted_by TEXT NOT NULL DEFAULT '',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, client_id)
);

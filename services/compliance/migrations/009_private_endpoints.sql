-- 009: approved private endpoints (7.40.0-beta).
--
-- A private address range a root administrator approved for one tenant's
-- source connections (git, s3, azure_blob, gcs). A source connection of
-- that tenant may name a host inside it, and discovery sends the
-- connection's credential to a private address only inside one. Rows hold
-- no credential.

CREATE TABLE IF NOT EXISTS compliance_private_endpoints (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    cidr TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, cidr)
);

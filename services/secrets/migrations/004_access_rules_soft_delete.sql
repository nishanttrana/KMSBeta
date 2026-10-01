-- Soft delete (7.28.0-beta): DELETE marks a secret deleted and keeps its
-- versions until it is restored or destroyed.
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP;
ALTER TABLE secrets ADD COLUMN IF NOT EXISTS deleted_by TEXT NOT NULL DEFAULT '';

-- Access rules (docs/SECURITY/SECRET_ACCESS.md): who may read, read the value
-- of, write or delete the secrets under a path. Replicated.
CREATE TABLE IF NOT EXISTS secret_access_rules (
    id           TEXT NOT NULL,
    tenant_id    TEXT NOT NULL,
    path         TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    effect       TEXT NOT NULL DEFAULT 'allow',
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

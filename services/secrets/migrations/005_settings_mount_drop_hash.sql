-- 7.30.0-beta.

-- Per-tenant vault settings (docs/SECURITY/SECRET_ACCESS.md): default-deny
-- for paths no access rule covers, a cap on stored versions, and how long a
-- deleted secret is kept before it is destroyed. Replicated.
CREATE TABLE IF NOT EXISTS secret_vault_settings (
    tenant_id              TEXT PRIMARY KEY,
    default_deny           BOOLEAN NOT NULL DEFAULT FALSE,
    max_versions           INTEGER NOT NULL DEFAULT 0,
    deleted_retention_days INTEGER NOT NULL DEFAULT 0,
    updated_by             TEXT NOT NULL DEFAULT '',
    updated_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The Vault KV routes used to ignore the mount: /v1/a/x and /v1/b/x were one
-- secret. A secret written under a mount other than "secret" is now named
-- <mount>/<path>, so it stays at the URL its client wrote it to. Each rename
-- is recorded in the secret's change history. A secret whose new name is
-- already taken is left as it is (reachable under the "secret" mount).
INSERT INTO secret_audit_log (id, tenant_id, secret_id, action, actor, detail, created_at)
SELECT 'aud_m005_' || s.id, s.tenant_id, s.id, 'renamed', 'system:migration-005',
       'Vault mount is now part of the name: ' || s.name || ' -> ' || (s.metadata::jsonb->>'mount') || '/' || s.name,
       CURRENT_TIMESTAMP
FROM secrets s
WHERE s.metadata::jsonb->>'vault_compat' = 'true'
  AND COALESCE(s.metadata::jsonb->>'mount', '') NOT IN ('', 'secret')
  AND s.name NOT LIKE (s.metadata::jsonb->>'mount') || '/%'
  AND NOT EXISTS (SELECT 1 FROM secrets o WHERE o.tenant_id = s.tenant_id AND o.name = (s.metadata::jsonb->>'mount') || '/' || s.name)
ON CONFLICT DO NOTHING;

UPDATE secrets s
SET name = (s.metadata::jsonb->>'mount') || '/' || s.name
WHERE s.metadata::jsonb->>'vault_compat' = 'true'
  AND COALESCE(s.metadata::jsonb->>'mount', '') NOT IN ('', 'secret')
  AND s.name NOT LIKE (s.metadata::jsonb->>'mount') || '/%'
  AND NOT EXISTS (SELECT 1 FROM secrets o WHERE o.tenant_id = s.tenant_id AND o.name = (s.metadata::jsonb->>'mount') || '/' || s.name);

-- value_hash was an unsalted SHA-256 of each secret value: with it, a copy of
-- the database is enough to test password guesses. Nothing reads it. Empty
-- it first so no live row keeps a hash, then drop the column.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = current_schema() AND table_name = 'secret_values' AND column_name = 'value_hash') THEN
        UPDATE secret_values SET value_hash = ''::bytea;
        ALTER TABLE secret_values DROP COLUMN value_hash;
    END IF;
END $$;

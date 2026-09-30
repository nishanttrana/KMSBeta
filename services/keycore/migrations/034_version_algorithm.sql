-- A rotation may change a key's algorithm under the same key ID: each version
-- records its own algorithm (NULL = the key's, set when the key moves on).
ALTER TABLE key_versions ADD COLUMN IF NOT EXISTS algorithm TEXT;

-- The record-only keycore migration plans are removed: progress was inferred
-- from tenant-wide algorithm counts. Migrations run in the pqc service.
DROP TABLE IF EXISTS agility_migration_plans;

-- 7.32.0-beta. When the scheduled check first found a rule's subject gone
-- (docs/SECURITY/SECRET_ACCESS.md); NULL while it exists.
ALTER TABLE secret_access_rules ADD COLUMN IF NOT EXISTS subject_missing_since TIMESTAMP;

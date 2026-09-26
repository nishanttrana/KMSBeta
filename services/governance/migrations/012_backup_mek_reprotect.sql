-- When a stored backup was last checked for rows under a retired public key
-- and re-protected (services/governance/backup_mek.go). NULL = not yet.
ALTER TABLE governance_backup_jobs ADD COLUMN IF NOT EXISTS mek_reprotected_at TIMESTAMPTZ;

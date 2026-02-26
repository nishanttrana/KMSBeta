ALTER TABLE approval_policies
    ADD COLUMN IF NOT EXISTS quorum_mode TEXT NOT NULL DEFAULT 'threshold';

UPDATE approval_policies
SET quorum_mode = 'threshold'
WHERE COALESCE(TRIM(quorum_mode), '') = '';

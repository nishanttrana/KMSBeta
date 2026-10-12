-- A key's description: display text set by whoever manages the key. No access
-- decision reads it (docs/SECURITY/KEY_ACCESS_MODEL.md section 6).
ALTER TABLE keys ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';

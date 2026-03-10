ALTER TABLE reporting_alert_rules ADD COLUMN IF NOT EXISTS expression TEXT NOT NULL DEFAULT '';

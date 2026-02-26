ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS approval_delivery_mode TEXT NOT NULL DEFAULT 'notify';

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS notify_slack BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS notify_teams BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS slack_webhook_url TEXT;

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS teams_webhook_url TEXT;

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS delivery_webhook_timeout_seconds INTEGER NOT NULL DEFAULT 5;

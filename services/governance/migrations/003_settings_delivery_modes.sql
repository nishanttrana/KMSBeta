ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS notify_dashboard BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS notify_email BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE governance_settings
    ADD COLUMN IF NOT EXISTS challenge_response_enabled BOOLEAN NOT NULL DEFAULT FALSE;

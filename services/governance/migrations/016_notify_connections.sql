-- Approval notices go through compliance connections (2.10.0-beta,
-- docs/SECURITY/CONNECTIONS.md). A Slack or Teams incoming-webhook URL is a
-- credential; it was stored here in plaintext. The migration job moves each
-- into a sealed connection (recorded in compliance's exposure register),
-- sets the ID below and clears the URL column.

ALTER TABLE governance_settings ADD COLUMN IF NOT EXISTS slack_connection_id TEXT NOT NULL DEFAULT '';
ALTER TABLE governance_settings ADD COLUMN IF NOT EXISTS teams_connection_id TEXT NOT NULL DEFAULT '';

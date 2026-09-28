-- Event streams send through a compliance connection (2.10.0-beta,
-- docs/SECURITY/CONNECTIONS.md). A stream names its connection; the URL,
-- format, secret and header columns stay only for rows an earlier release
-- wrote, until the migration job moves their credentials into a connection
-- and clears them. connection_type is the connection's type when the
-- stream was saved, for display. Replicated.

ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS connection_id TEXT NOT NULL DEFAULT '';
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS connection_type TEXT NOT NULL DEFAULT '';

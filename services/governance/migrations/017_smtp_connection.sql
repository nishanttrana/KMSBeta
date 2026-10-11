-- The mail relay is a credential in the credential store (8.0.0-beta).
--
-- Governance settings name an "smtp" credential (Playbooks → Credentials) by
-- ID. The relay's host, account and password, which this table stored in
-- plaintext, are moved there by the primary (recorded as exposed when a
-- password was stored) and the smtp_* columns are then cleared.
--
-- Schema only: the table is replicated (pkg/clustercatalog).
ALTER TABLE governance_settings ADD COLUMN IF NOT EXISTS smtp_connection_id TEXT NOT NULL DEFAULT '';

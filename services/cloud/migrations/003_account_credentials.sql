-- Cloud account credentials live in the credential store (7.38.0-beta).
--
-- A cloud account names a credential (Playbooks → Credentials) by ID and the
-- cloud service opens it for each provider call. The sealed copy this table
-- used to hold is moved into the store by the primary and the columns are
-- then cleared, so they can be empty.
--
-- Schema only: the table is replicated (pkg/clustercatalog).
ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS connection_id TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_accounts ALTER COLUMN creds_wrapped_dek DROP NOT NULL;
ALTER TABLE cloud_accounts ALTER COLUMN creds_wrapped_dek_iv DROP NOT NULL;
ALTER TABLE cloud_accounts ALTER COLUMN creds_ciphertext DROP NOT NULL;
ALTER TABLE cloud_accounts ALTER COLUMN creds_data_iv DROP NOT NULL;

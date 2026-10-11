-- Azure EKM app registration lives in the credential store (8.0.0-beta).
--
-- A vault configuration names an "azure" credential (Playbooks →
-- Credentials) by ID. The client secret this table stored in plaintext is
-- moved there by the primary, recorded as exposed (database copies and
-- backups made before still hold it), and this column is then emptied.
--
-- Schema only: the table is replicated (pkg/clustercatalog).
ALTER TABLE ekm_azure_configs ADD COLUMN IF NOT EXISTS connection_id TEXT NOT NULL DEFAULT '';

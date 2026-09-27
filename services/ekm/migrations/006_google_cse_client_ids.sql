-- Google CSE: the OAuth client IDs an authentication token's aud must name.
-- Existing configs get none and admit nobody until an administrator sets
-- them (fail closed; docs/SECURITY/REAL_CAPABILITY.md).
ALTER TABLE ekm_google_cse_configs ADD COLUMN IF NOT EXISTS authentication_client_ids TEXT NOT NULL DEFAULT '[]';

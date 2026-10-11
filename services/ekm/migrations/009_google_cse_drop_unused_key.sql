-- Google CSE: stop holding a service account key nothing uses (8.0.0-beta).
--
-- The Google CSE dialog collected a service account key file and this table
-- stored it in plaintext. No code ever read it: the KACLS verifies Google's
-- and the identity provider's tokens against their published keys and needs
-- no Google credential of its own. The stored keys are removed; the API no
-- longer accepts the field. Copies remain in older database backups, so the
-- key should be deleted in Google Cloud (see CHANGELOG 8.0.0-beta).
UPDATE ekm_google_cse_configs SET service_account_key_json = '' WHERE service_account_key_json <> '';

ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS cryptographically_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS verification_mode TEXT NOT NULL DEFAULT '';
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS verification_issuer TEXT NOT NULL DEFAULT '';
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS verification_key_id TEXT NOT NULL DEFAULT '';
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS attestation_document_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS attestation_document_format TEXT NOT NULL DEFAULT '';

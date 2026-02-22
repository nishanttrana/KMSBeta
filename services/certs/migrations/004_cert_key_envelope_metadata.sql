ALTER TABLE cert_cas
ADD COLUMN IF NOT EXISTS signer_kek_version TEXT NOT NULL DEFAULT 'legacy-v1';

ALTER TABLE cert_cas
ADD COLUMN IF NOT EXISTS signer_fingerprint_sha256 TEXT NOT NULL DEFAULT '';


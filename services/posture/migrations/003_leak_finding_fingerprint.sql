-- 003: add a non-reversible fingerprint of the matched secret to leak
-- findings. This is the join key the unified Threat & Exposure console uses
-- to correlate a leaked credential with the KMS key that protects it, via
-- keycore's external_credential_bindings registry. It is a SHA-256 hex
-- digest of the raw secret value, so it exposes nothing on its own.

ALTER TABLE leak_findings ADD COLUMN IF NOT EXISTS secret_fingerprint TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_leak_findings_fingerprint
    ON leak_findings(tenant_id, secret_fingerprint);

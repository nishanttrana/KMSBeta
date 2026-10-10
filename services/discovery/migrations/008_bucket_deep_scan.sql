-- 008: deep scan for buckets (7.37.0-beta).
--
-- deep_scan: the scan also reads the first kilobyte of every object whose
-- name does not say what it is, and scans those that hold key material
-- (a PEM block, a keystore, an SSH key, an archive). One small request per
-- such object, so it is off unless the tenant turns it on for the bucket.

ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS deep_scan BOOLEAN NOT NULL DEFAULT FALSE;

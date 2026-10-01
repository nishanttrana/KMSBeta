-- 005: SSH targets and address ranges for the network scan (7.18.0-beta).
--
-- A target's host can now be a CIDR range (at most 256 addresses) and its
-- protocol "ssh": the scan reads the server's offered key exchange, cipher
-- and MAC algorithms and its host keys (services/discovery/ssh.go). Rows
-- from before are TLS targets.

ALTER TABLE discovery_scan_targets ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'tls';

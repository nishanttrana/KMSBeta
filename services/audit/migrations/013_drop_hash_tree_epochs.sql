-- 013: remove the hash-tree epoch tables (3.0.0-beta).
--
-- Audit tamper evidence is the SHA-256 hash chain, the per-event HMAC and
-- signed checkpoints: every checkpoint interval each node signs the head of
-- each chain it appends with an in-memory ECDSA-P384 key, recorded as the
-- audit event audit.audit.checkpoint_signed (services/audit/checkpoint.go,
-- docs/SECURITY/AUDIT_INTEGRITY.md). The epoch tables were built hourly but
-- nothing outside the service ever held a root, and their verify endpoint
-- accepted any root the caller sent. Migration 002, which created them, is
-- removed and 004/005 no longer alter them; this drops them where they exist.

DROP TABLE IF EXISTS audit_merkle_leaves;
DROP TABLE IF EXISTS audit_merkle_epochs;

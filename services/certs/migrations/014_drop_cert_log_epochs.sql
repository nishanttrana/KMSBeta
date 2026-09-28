-- 014: remove the internal certificate hash-tree log (3.0.0-beta).
--
-- It hashed issued certificates into epochs that nothing outside the service
-- ever held, and its verify endpoint accepted any root the caller sent, so it
-- proved nothing to an auditor. Issuance, renewal and revocation are audit
-- events, protected by the audit chain, its HMACs and signed checkpoints
-- (docs/SECURITY/AUDIT_INTEGRITY.md). Migration 006, which created the
-- tables, is removed; this drops them where they exist.

DROP TABLE IF EXISTS cert_merkle_leaves;
DROP TABLE IF EXISTS cert_merkle_epochs;

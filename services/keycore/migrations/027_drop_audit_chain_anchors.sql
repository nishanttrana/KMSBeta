-- 027: remove the audit-chain anchor preview (3.1.0-beta).
--
-- Anchors recorded an external reference in a local hash chain of anchor
-- records; nothing was anchored externally and nothing verified them. The
-- audit service's signed checkpoints are the real tamper evidence
-- (docs/SECURITY/AUDIT_INTEGRITY.md). Migration 011 no longer creates the
-- table and 018 (relabel) is removed; this drops it where it exists.

DROP TABLE IF EXISTS key_audit_chain_anchors;

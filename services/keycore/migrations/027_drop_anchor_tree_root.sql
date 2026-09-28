-- 027: drop the audit-chain anchor's tree-root column (3.0.0-beta).
--
-- The column held a root computed from tenant/type/reference/time, never from
-- audit events; migration 018 blanked it. Audit tamper evidence is the audit
-- service's hash chain, per-event HMAC and signed checkpoints
-- (docs/SECURITY/AUDIT_INTEGRITY.md). Migration 011 no longer creates the
-- column; this drops it where it exists, and renames the old default anchor
-- type to "local".

ALTER TABLE key_audit_chain_anchors DROP COLUMN IF EXISTS merkle_root;
UPDATE key_audit_chain_anchors SET anchor_type = 'local' WHERE anchor_type = 'internal_merkle';

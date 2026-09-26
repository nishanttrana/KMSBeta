-- 022: remove the general key escrow workflow.
--
-- Guardians, escrow policies, "escrowed" keys and recovery votes were
-- records only: no key material was split or released, and guardian votes
-- weren't bound to the caller's identity. Recovery of a lost platform is
-- covered by backups, whose key can be split into M-of-N guardian shares
-- (governance, docs/SECURITY/BACKUP_KEYS.md).

DROP TABLE IF EXISTS escrow_recovery_requests;
DROP TABLE IF EXISTS escrowed_keys;
DROP TABLE IF EXISTS escrow_policies;
DROP TABLE IF EXISTS escrow_guardians;
DELETE FROM enterprise_control_records WHERE category IN ('escrow_tier', 'escrow_shamir');

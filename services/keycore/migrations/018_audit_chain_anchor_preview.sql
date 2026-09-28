-- Audit-chain anchors are a preview feature (pkg/features, docs/PREVIEW_FEATURES.md).
-- Earlier rows reported a tree root computed from tenant/type/reference/time
-- and the status "anchored"; neither was true. Relabel them honestly (the
-- root column itself is dropped by migration 027).
-- anchor_hash (the local chain of anchor records) is unchanged.
UPDATE key_audit_chain_anchors SET status = 'recorded' WHERE status = 'anchored';

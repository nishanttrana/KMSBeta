-- Audit-chain anchors are a preview feature (pkg/features, docs/PREVIEW_FEATURES.md).
-- Earlier rows reported a "merkle_root" computed from tenant/type/reference/
-- time and the status "anchored"; neither was true. Relabel them honestly.
-- anchor_hash (the local chain of anchor records) is unchanged.
UPDATE key_audit_chain_anchors SET merkle_root = '', status = 'recorded' WHERE status = 'anchored' OR merkle_root <> '';

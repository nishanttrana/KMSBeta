-- 016: remove the key binding and key metadata-extension features.
--
-- key_binding_configs stored TPM/PCR, region and IP-CIDR "bindings" that were
-- never enforced at crypto time — decorative config that did nothing.
-- key_metadata_ext duplicated governance fields the key already carries
-- (owner, tags, labels, compliance). Both are dropped; the surviving
-- lifecycle assurance feature is real key-integrity verification, which needs
-- no table.

DROP TABLE IF EXISTS key_binding_configs;
DROP TABLE IF EXISTS key_metadata_ext;

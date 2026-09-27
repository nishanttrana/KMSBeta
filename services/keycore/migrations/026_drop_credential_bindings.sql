-- 026: remove the external credential -> key binding registry.
--
-- It existed only so the leak scanner's findings could be correlated with the
-- key protecting a leaked credential. The leak scanner is removed
-- (docs/DECISIONS.md, 2.0.0-beta), so the registry and the wrap-time
-- auto-registration go with it. Nothing stored here was key material: only
-- SHA-256 fingerprints.

DROP TABLE IF EXISTS external_credential_bindings;

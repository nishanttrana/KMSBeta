-- 003: remove the tenant PQC policy and the readiness score (6.3.0-beta).
--
-- Nothing enforced the policy: require_pqc_for_new_keys never reached key
-- creation, the profile, default KEM/signature and HQC switch changed
-- nothing but recommendation text, interface_default_mode was reported as
-- the TLS mode of interfaces nobody measured, and the three flag_* switches
-- only hid findings from the inventory. Requiring PQC for new protection is
-- a Crypto Agility migration rule that keycore enforces.
--
-- readiness_score was a hand-weighted blend (55/30/15) of counts the scan
-- row already stores; the counts remain.

DROP TABLE IF EXISTS pqc_policies;
ALTER TABLE pqc_readiness_scans DROP COLUMN IF EXISTS readiness_score;

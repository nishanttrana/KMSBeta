-- 011: remove the CT log monitor.
--
-- It never read a Certificate Transparency log: adding a domain generated
-- synthetic certificates (including an invented "UnknownCA-ShadowNet"
-- issuer) and raised high-severity mis-issuance alerts from them. Dropping
-- the tables also purges those fabricated entries and alerts.

DROP TABLE IF EXISTS ct_alerts;
DROP TABLE IF EXISTS ct_log_entries;
DROP TABLE IF EXISTS ct_watched_domains;

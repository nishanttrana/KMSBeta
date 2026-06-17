-- 017: remove the standalone KDF configuration feature.
--
-- Key derivation is a crypto-library operation already exposed as the
-- POST /keys/{id}/derive op (and through the REST / PKCS#11 / JCA interfaces).
-- The kdf_configs "named configuration" feature was a redundant management
-- surface for the same primitive, so it is dropped along with its tab.

DROP TABLE IF EXISTS kdf_derivation_log;
DROP TABLE IF EXISTS kdf_configs;

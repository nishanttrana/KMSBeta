-- 024: remove the keycore "envelope hierarchy" (KEKs, DEKs, rewrap jobs).
--
-- A KEK here was a name/version row with no key material, "rotate" only
-- incremented the version, nothing ever inserted a DEK, and nothing ran a
-- rewrap job. Envelope encryption is served by real keycore keys:
-- POST /keys/{id}/generate-data-key and /keys/{id}/decrypt-data-key, and
-- dataprotect /app/envelope-encrypt|decrypt.

DROP TABLE IF EXISTS envelope_rewrap_jobs;
DROP TABLE IF EXISTS envelope_deks;
DROP TABLE IF EXISTS envelope_keks;

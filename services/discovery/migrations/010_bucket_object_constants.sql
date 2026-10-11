-- Constants shared between a bucket's objects (9.2.0-beta). A call in one
-- object can name its algorithm through a constant another object defines.
-- Each object read records the constants it defines for others
-- (consts_json: name to literals), the constant names it reads and does not
-- define (needs), and a hash of what those stood for when it was read
-- (needs_hash). An unchanged object is read again when that hash no longer
-- matches. No source line is stored. Replicated with the table.

ALTER TABLE discovery_bucket_objects ADD COLUMN IF NOT EXISTS consts_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE discovery_bucket_objects ADD COLUMN IF NOT EXISTS needs TEXT NOT NULL DEFAULT '';
ALTER TABLE discovery_bucket_objects ADD COLUMN IF NOT EXISTS needs_hash TEXT NOT NULL DEFAULT '';

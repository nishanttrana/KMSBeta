-- 004: remove the leak scanner.
--
-- It scanned pasted text or a folder on the posture host, which is not a
-- credible place for secret scanning: that belongs in CI tooling that sees
-- the repositories and images. Its targets, jobs and findings go with it
-- (docs/DECISIONS.md, 2.0.0-beta).

DROP TABLE IF EXISTS leak_findings;
DROP TABLE IF EXISTS leak_scan_jobs;
DROP TABLE IF EXISTS leak_scan_targets;

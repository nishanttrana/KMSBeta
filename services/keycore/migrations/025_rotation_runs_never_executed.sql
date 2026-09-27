-- Before 1.20.0-beta, POST /rotation/policies/{id}/trigger inserted a run
-- marked 'running' and rotated nothing. Close those rows honestly.
UPDATE rotation_runs
SET status = 'failed',
    completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
    error = 'not executed: recorded by a trigger that did not rotate keys (fixed in 1.20.0-beta)'
WHERE status = 'running';

-- Runs and restore points written before 2026-09-25 were simulated: random
-- key counts and sizes, no backup file, and a restore that did nothing
-- (docs/PREVIEW_FEATURES.md). Mark them so no report counts them as real.
UPDATE backup_runs SET status = 'simulated',
    error = 'simulated run: no backup was taken (backup scheduler is a preview feature)'
WHERE status <> 'simulated';
UPDATE backup_restore_points SET status = 'simulated' WHERE status <> 'simulated';

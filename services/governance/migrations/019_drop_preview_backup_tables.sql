-- The backup scheduler preview (services/backup) is removed (13.43.0-beta):
-- it stored policies, runs and restore points and never took a backup.
-- Scheduled backups are governance's own (018_backup_schedules.sql). Its
-- tables are dropped here: the service that owned them is gone, and what
-- they held was never a backup.
DROP TABLE IF EXISTS backup_restore_points;
DROP TABLE IF EXISTS backup_runs;
DROP TABLE IF EXISTS backup_policies;

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Driver string

const (
	DriverPostgres Driver = "pgx"
	DriverSQLite   Driver = "sqlite"
)

type Config struct {
	PostgresDSN     string
	PostgresRODSN   string // read-only replica DSN (empty = disabled)
	SQLitePath      string
	UseSQLite       bool
	MaxOpen         int
	MaxIdle         int
	ConnMaxIdleTime time.Duration
	ConnMaxLifetime time.Duration
}

type DB struct {
	driver Driver
	sqlDB  *sql.DB
	roDB   *sql.DB // read-only replica (nil if not configured)
}

func Open(ctx context.Context, cfg Config) (*DB, error) {
	driver := DriverPostgres
	dsn := cfg.PostgresDSN
	if cfg.UseSQLite {
		driver = DriverSQLite
		if cfg.SQLitePath == "" {
			cfg.SQLitePath = "vecta.db"
		}
		dsn = cfg.SQLitePath
	}

	// Mask password in DSN for logging
	logDSN := dsn
	if driver == DriverPostgres {
		if idx := strings.Index(logDSN, "://"); idx >= 0 {
			if atIdx := strings.Index(logDSN[idx:], "@"); atIdx >= 0 {
				logDSN = logDSN[:idx+3] + "***@" + logDSN[idx+atIdx+1:]
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[db] opening driver=%s dsn=%s\n", driver, logDSN)

	conn, err := sql.Open(string(driver), dsn)
	if err != nil {
		return nil, fmt.Errorf("db open (driver=%s): %w", driver, err)
	}

	applyPoolSettings(conn, cfg)

	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("db ping (driver=%s): %w", driver, err)
	}

	// Log the actual database we're connected to
	if driver == DriverPostgres {
		var dbName string
		if err := conn.QueryRowContext(ctx, "SELECT current_database()").Scan(&dbName); err == nil {
			fmt.Fprintf(os.Stderr, "[db] connected driver=%s database=%s\n", driver, dbName)
		} else {
			fmt.Fprintf(os.Stderr, "[db] connected driver=%s (could not read db name: %v)\n", driver, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "[db] connected driver=%s\n", driver)
	}
	d := &DB{driver: driver, sqlDB: conn}

	// Open read-only replica if configured
	if cfg.PostgresRODSN != "" && !cfg.UseSQLite {
		roConn, err := sql.Open(string(DriverPostgres), cfg.PostgresRODSN)
		if err == nil {
			applyPoolSettings(roConn, cfg)
			if pingErr := roConn.PingContext(ctx); pingErr == nil {
				d.roDB = roConn
			} else {
				_ = roConn.Close()
			}
		}
	}

	return d, nil
}

func applyPoolSettings(conn *sql.DB, cfg Config) {
	maxOpen := cfg.MaxOpen
	if maxOpen <= 0 {
		maxOpen = 50
	}
	maxIdle := cfg.MaxIdle
	if maxIdle <= 0 {
		maxIdle = 25
	}
	conn.SetMaxOpenConns(maxOpen)
	conn.SetMaxIdleConns(maxIdle)

	if cfg.ConnMaxLifetime > 0 {
		conn.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	} else {
		conn.SetConnMaxLifetime(30 * time.Minute)
	}
	if cfg.ConnMaxIdleTime > 0 {
		conn.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	} else {
		conn.SetConnMaxIdleTime(5 * time.Minute)
	}
}

func (d *DB) SQL() *sql.DB {
	return d.sqlDB
}

// ROSQL returns the read-only replica connection if available, else the primary.
func (d *DB) ROSQL() *sql.DB {
	if d.roDB != nil {
		return d.roDB
	}
	return d.sqlDB
}

func (d *DB) Close() error {
	if d == nil || d.sqlDB == nil {
		return nil
	}
	if d.roDB != nil {
		_ = d.roDB.Close()
	}
	return d.sqlDB.Close()
}

func (d *DB) WithTenantTx(ctx context.Context, tenantID string, fn func(tx *sql.Tx) error) error {
	if tenantID == "" {
		return errors.New("tenant_id is required")
	}
	tx, err := d.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if d.driver == DriverPostgres {
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
			return err
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// RunMigrations applies pending SQL migrations from migrationsDir in filename
// order (001_*.sql, 002_*.sql, …).  Each migration is recorded in the
// schema_migrations table so it is executed exactly once, even if the process
// restarts mid-run.  A PostgreSQL advisory lock (key 9876543210) prevents two
// services from running migrations concurrently during a rolling deploy.
func (d *DB) RunMigrations(ctx context.Context, migrationsDir string) error {
	fmt.Fprintf(os.Stderr, "[db] running migrations from %s (driver=%s)\n", migrationsDir, d.driver)
	if d.driver == DriverPostgres {
		// Acquire an instance-level advisory lock for the duration of migration.
		// pg_try_advisory_lock returns false immediately if another session holds
		// the lock, so we spin with a short back-off rather than blocking forever.
		const lockKey = 9876543210
		for attempt := 0; attempt < 30; attempt++ {
			var locked bool
			if err := d.sqlDB.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&locked); err != nil {
				return fmt.Errorf("migration lock acquire: %w", err)
			}
			if locked {
				break
			}
			if attempt == 29 {
				return fmt.Errorf("migration: could not acquire advisory lock after 30 attempts")
			}
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
		defer d.sqlDB.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", lockKey) //nolint:errcheck
	}

	// Ensure the tracking table exists (idempotent).
	const createTracking = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`
	if _, err := d.sqlDB.ExecContext(ctx, createTracking); err != nil {
		return fmt.Errorf("migration: create tracking table: %w", err)
	}
	// Verify the tracking table actually exists and count rows
	var migCount int
	if err := d.sqlDB.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migCount); err != nil {
		fmt.Fprintf(os.Stderr, "[db] WARNING: schema_migrations query failed: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "[db] schema_migrations table ensured, existing rows=%d\n", migCount)
	}
	// Also verify by checking pg_tables
	if d.driver == DriverPostgres {
		var tableExists bool
		d.sqlDB.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='schema_migrations')").Scan(&tableExists)
		fmt.Fprintf(os.Stderr, "[db] pg_tables confirms schema_migrations exists=%v\n", tableExists)
	}

	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("migration: read dir %s: %w", migrationsDir, err)
	}
	var sqlFiles []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".sql") {
			sqlFiles = append(sqlFiles, filepath.Join(migrationsDir, f.Name()))
		}
	}
	sort.Strings(sqlFiles)
	fmt.Fprintf(os.Stderr, "[db] found %d migration files\n", len(sqlFiles))

	for _, path := range sqlFiles {
		name := filepath.Base(path)

		// Skip already-applied migrations.
		var applied bool
		if err := d.sqlDB.QueryRowContext(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE filename = $1)", name,
		).Scan(&applied); err != nil {
			return fmt.Errorf("migration: check %s: %w", name, err)
		}
		if applied {
			fmt.Fprintf(os.Stderr, "[db] migration %s already applied, skipping\n", name)
			continue
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[db] applying migration %s (%d bytes)\n", name, len(b))
		if _, err := d.sqlDB.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("migration %s failed: %w", name, err)
		}
		fmt.Fprintf(os.Stderr, "[db] migration %s applied OK\n", name)

		// Record the migration as applied.
		if _, err := d.sqlDB.ExecContext(ctx,
			"INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING", name,
		); err != nil {
			return fmt.Errorf("migration: record %s: %w", name, err)
		}
	}
	return nil
}

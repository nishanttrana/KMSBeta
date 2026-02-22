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
	PostgresDSN string
	SQLitePath  string
	UseSQLite   bool
	MaxOpen     int
	MaxIdle     int
}

type DB struct {
	driver Driver
	sqlDB  *sql.DB
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

	conn, err := sql.Open(string(driver), dsn)
	if err != nil {
		return nil, err
	}

	// Keep pool conservative for PgBouncer transaction pooling mode.
	if cfg.MaxOpen <= 0 {
		cfg.MaxOpen = 20
	}
	if cfg.MaxIdle <= 0 {
		cfg.MaxIdle = 10
	}
	conn.SetMaxOpenConns(cfg.MaxOpen)
	conn.SetMaxIdleConns(cfg.MaxIdle)
	conn.SetConnMaxLifetime(30 * time.Minute)

	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &DB{driver: driver, sqlDB: conn}, nil
}

func (d *DB) SQL() *sql.DB {
	return d.sqlDB
}

func (d *DB) Close() error {
	if d == nil || d.sqlDB == nil {
		return nil
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

func (d *DB) RunMigrations(ctx context.Context, migrationsDir string) error {
	files, err := os.ReadDir(migrationsDir)
	if err != nil {
		return err
	}
	var sqlFiles []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".sql") {
			sqlFiles = append(sqlFiles, filepath.Join(migrationsDir, f.Name()))
		}
	}
	sort.Strings(sqlFiles)
	for _, f := range sqlFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := d.sqlDB.ExecContext(ctx, string(b)); err != nil {
			return fmt.Errorf("migration %s failed: %w", f, err)
		}
	}
	return nil
}

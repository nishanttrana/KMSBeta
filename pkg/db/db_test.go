package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationScopeUsesServicePath(t *testing.T) {
	got := migrationScope(filepath.Join("services", "auth", "migrations"))
	if got != "services/auth" {
		t.Fatalf("migrationScope() = %q, want %q", got, "services/auth")
	}
}

func TestMigrationScopeFallsBackToExecutableName(t *testing.T) {
	originalArgs := append([]string(nil), os.Args...)
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	os.Args = []string{"/app/kms-keycore"}
	got := migrationScope("/app/migrations")
	if got != "services/keycore" {
		t.Fatalf("migrationScope() = %q, want %q", got, "services/keycore")
	}
}

func TestRunMigrationsNamespacesDuplicateFilenames(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	sqlitePath := filepath.Join(root, "test.db")

	dbConn, err := Open(ctx, Config{
		UseSQLite:  true,
		SQLitePath: sqlitePath,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer dbConn.Close() //nolint:errcheck

	authDir := filepath.Join(root, "services", "auth", "migrations")
	keycoreDir := filepath.Join(root, "services", "keycore", "migrations")
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(authDir) error = %v", err)
	}
	if err := os.MkdirAll(keycoreDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(keycoreDir) error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(authDir, "001_initial.sql"), []byte(`
CREATE TABLE IF NOT EXISTS auth_users (
    id TEXT PRIMARY KEY
);
`), 0o644); err != nil {
		t.Fatalf("WriteFile(auth migration) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(keycoreDir, "001_initial.sql"), []byte(`
CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY
);
`), 0o644); err != nil {
		t.Fatalf("WriteFile(keycore migration) error = %v", err)
	}

	if err := dbConn.RunMigrations(ctx, authDir); err != nil {
		t.Fatalf("RunMigrations(auth) error = %v", err)
	}
	if err := dbConn.RunMigrations(ctx, keycoreDir); err != nil {
		t.Fatalf("RunMigrations(keycore) error = %v", err)
	}

	for _, tableName := range []string{"auth_users", "keys"} {
		var exists int
		if err := dbConn.SQL().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = $1", tableName).Scan(&exists); err != nil {
			t.Fatalf("table lookup for %s failed: %v", tableName, err)
		}
		if exists != 1 {
			t.Fatalf("table %s missing after migrations", tableName)
		}
	}

	var count int
	if err := dbConn.SQL().QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("schema_migrations count failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("schema_migrations count = %d, want 2", count)
	}
}

package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Migration 004 on real Postgres (CI integration-postgres): retired channel
// rows (paging, chat, email) are deleted and the dashboard feed is kept.
func TestRetiredChannelsDeletedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	tenant := "t-rep-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, name := range []string{"pager", "Email ", "slack", "screen"} {
		if _, err := conn.SQL().Exec(`INSERT INTO reporting_notification_channels (tenant_id, name, config_json) VALUES ($1, $2, '{"routing_key":"x"}')`, tenant, name); err != nil {
			t.Fatal(err)
		}
	}
	migration, err := os.ReadFile("migrations/004_drop_retired_channels.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().Exec(string(migration)); err != nil {
		t.Fatal(err)
	}
	var names []string
	rows, err := conn.SQL().Query(`SELECT name FROM reporting_notification_channels WHERE tenant_id=$1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		names = append(names, n)
	}
	if strings.Join(names, ",") != "screen" {
		t.Fatalf("channels left after migration 004: %v", names)
	}
}

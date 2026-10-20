package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// The 24-hour summary counts every decision in the window, in the database:
// it counted the newest 100 rows (13.24.0-beta). Real Postgres, real schema.
func TestSummaryCountsEveryDecisionPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `DELETE FROM key_access_decisions WHERE tenant_id='sum-t'`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	insert := func(id, service, decision, reason string, bypass bool, at time.Time) {
		t.Helper()
		if _, err := conn.SQL().ExecContext(ctx, `INSERT INTO key_access_decisions (id, tenant_id, service_name, operation, decision, reason, bypass_detected, created_at)
VALUES ($1,'sum-t',$2,'decrypt',$3,$4,$5,$6)`, id, service, decision, reason, bypass, at); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 600; i++ { // more than one 500-row list
		insert(fmt.Sprintf("a%03d", i), "ekm", "allow", "", false, now.Add(-time.Duration(i)*time.Second))
	}
	insert("d1", "hyok", "deny", "missing justification", false, now.Add(-time.Hour))
	insert("d2", "hyok", "deny", "unknown_code: X", true, now.Add(-time.Hour))
	insert("d3", "hyok", "deny", "unknownXcode", false, now.Add(-time.Hour)) // "_" is not a wildcard
	insert("p1", "byok", "approval", "", false, now.Add(-2*time.Hour))
	insert("old", "ekm", "allow", "", false, now.Add(-25*time.Hour)) // outside the window

	svc := NewService(NewSQLStore(conn), nil)
	sum, err := svc.GetSummary(ctx, "sum-t")
	if err != nil {
		t.Fatal(err)
	}
	if sum.TotalRequests24h != 604 || sum.AllowCount24h != 600 || sum.DenyCount24h != 3 || sum.ApprovalCount24h != 1 ||
		sum.BypassCount24h != 1 || sum.UnjustifiedCount24h != 2 {
		t.Fatalf("summary over every decision in the window: %+v", sum)
	}
	if len(sum.Services) != 3 || sum.Services[0].Service != "byok" || sum.Services[1].Requests24h != 600 || sum.Services[2].UnjustifiedCount24h != 2 {
		t.Fatalf("per service: %+v", sum.Services)
	}
}

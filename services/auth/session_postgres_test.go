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

// A refresh renews a session on the RLS-enabled auth_sessions table on real
// Postgres (CI integration-postgres), and an ended session renews nothing.
func TestSessionRenewalPostgres(t *testing.T) {
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
	s := NewSQLStore(conn)
	tenant := "t-sess-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := s.CreateTenant(ctx, Tenant{ID: tenant, Name: tenant, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{ID: "u-" + tenant, TenantID: tenant, Username: "u-" + tenant, Email: "u@example.com", Role: "tenant-admin", Status: "active", Password: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	sid := "sess_" + tenant
	if err := s.CreateSession(ctx, Session{ID: sid, TenantID: tenant, UserID: "u-" + tenant, TokenHash: []byte("h1"), IPAddress: "198.51.100.7", ExpiresAt: time.Now().Add(15 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.TouchSession(ctx, tenant, sid, []byte("h2"), time.Now().Add(30*time.Minute)); err != nil || !ok {
		t.Fatalf("renewing a live session = %v, %v", ok, err)
	}
	if ok, err := s.TouchSession(ctx, "other-"+tenant, sid, []byte("h3"), time.Now()); err != nil || ok {
		t.Fatalf("another tenant renewed the session: %v, %v", ok, err)
	}
	if err := s.DeleteSession(ctx, tenant, sid); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.TouchSession(ctx, tenant, sid, []byte("h4"), time.Now()); err != nil || ok {
		t.Fatalf("renewing an ended session = %v, %v", ok, err)
	}
}

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

// Postgres keeps source_ip as INET, which reads back as text with its prefix
// length ("192.0.2.1/32"), while the chain hash covers the bare address.
// Until 13.42.0-beta every event with an address failed the chain walk on
// Postgres, live included, and no test stored an address. Events with an
// IPv4 and an IPv6 address verify, read back without the prefix, and an
// address changed in the table is still a break.
func TestChainVerifiesEventsWithAnAddressPostgres(t *testing.T) {
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
		t.Fatalf("migrations: %v", err)
	}
	s := NewSQLStore(conn)
	tenant := "t-addr-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	for _, ip := range []string{"192.0.2.10", "2001:db8::7", "198.51.100.4:51000", ""} {
		if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: tenant, Timestamp: time.Now().UTC(), Service: "keycore",
			Action: "audit.key.create", ActorID: "u1", ActorType: "user", Result: "success", SourceIP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, breaks, err := s.VerifyChain(ctx, tenant); err != nil || !ok {
		t.Fatalf("a chain of events with addresses must verify: ok=%v breaks=%v err=%v", ok, breaks, err)
	}
	events, err := s.QueryEvents(ctx, tenant, EventQuery{Limit: 10, Ascending: true})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range events {
		got = append(got, e.SourceIP)
	}
	if strings.Join(got, ",") != "192.0.2.10,2001:db8::7,198.51.100.4," {
		t.Fatalf("addresses read back as %q", got)
	}

	// The address is covered by the hash: changing it is a break. The
	// immutability trigger refuses the edit; a superuser bypassing it is
	// caught by the walk.
	tx, err := conn.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL session_replication_role = replica`); err != nil {
		_ = tx.Rollback()
		t.Skipf("test role cannot bypass triggers: %v", err)
	}
	if _, err := tx.Exec(`UPDATE audit_events SET source_ip='203.0.113.66' WHERE tenant_id=$1 AND sequence=1`, tenant); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	ok, breaks, err := s.VerifyChain(ctx, tenant)
	if err != nil || ok || len(breaks) == 0 || breaks[0]["reason"] != "chain_hash_mismatch" {
		t.Fatalf("a changed address must break the chain: ok=%v breaks=%v err=%v", ok, breaks, err)
	}
}

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

// Key visibility on real Postgres: group grants from key_access_group_members
// (JSONB operations), the scoped IN query, and cursor paging over a
// restricted caller's keys (CI integration-postgres).
func TestKeyVisibilityPostgres(t *testing.T) {
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
	svc := NewService(NewSQLStore(conn), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	tenant := "t-vis-pg-" + strings.ToLower(newID("x")[2:10])

	create := func(name, creator string) Key {
		k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: name, Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: creator})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond) // distinct created_at for the cursor
		return k
	}
	for _, n := range []string{"a1", "a2", "a3"} {
		create(n, "alice")
	}
	viaGroup := create("b-group", "bob")
	hidden := create("b-hidden", "bob")

	group, err := svc.store.CreateAccessGroup(ctx, AccessGroup{TenantID: tenant, ID: newID("grp"), Name: "crypto-ops", CreatedBy: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.ReplaceAccessGroupMembers(ctx, tenant, group.ID, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.ReplaceKeyAccessGrants(ctx, tenant, viaGroup.ID, []KeyAccessGrant{
		{SubjectType: AccessSubjectGroup, SubjectID: group.ID, Operations: []string{"decrypt"}},
	}, "bob"); err != nil {
		t.Fatal(err)
	}

	claims := &pkgauth.Claims{UserID: "alice", TenantID: tenant, Role: "operator"}
	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	actx := contextWithAccessActor(req.Context(), accessActorFromHTTPRequest(req))
	view, err := svc.keyViewFor(actx, tenant)
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	var after *time.Time
	afterID := ""
	for pages := 0; pages < 5; pages++ {
		page, err := svc.ListKeysCursor(ctx, tenant, view, 2, after, afterID, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		for _, k := range page {
			if seen[k.Name] {
				t.Fatalf("cursor repeated %s", k.Name)
			}
			seen[k.Name] = true
		}
		last := page[len(page)-1]
		after, afterID = &last.CreatedAt, last.ID
	}
	if len(seen) != 4 || !seen["b-group"] || seen["b-hidden"] {
		t.Fatalf("alice paged through %v, want a1-a3 and b-group", seen)
	}
	if err := svc.ensureKeyVisible(actx, hidden); err != errStoreNotFound {
		t.Fatalf("hidden key readable: %v", err)
	}
	if err := svc.ensureKeyVisible(actx, viaGroup); err != nil {
		t.Fatalf("group-granted key hidden: %v", err)
	}
}

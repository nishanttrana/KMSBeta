package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

// Binding policies on Postgres (CI integration-postgres): migration 037,
// every list and the selector read back, and a binding refusing a key.
func TestKeyBindingPoliciesPostgres(t *testing.T) {
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
	tenant := "t-bind-pg-" + strings.ToLower(newID("x")[2:10])
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: "k", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Labels: map[string]string{"env": "prod"}, CreatedBy: "u"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := KeyBindingPolicy{ID: newID("kbp"), TenantID: tenant, Name: "pg", LabelSelector: map[string]string{"env": "prod"},
		Channels: []string{"kms-kmip"}, SourceNetworks: []string{"10.0.0.0/8"}, WorkloadIdentities: []string{"spiffe://x/*"},
		CreatedBy: "u", UpdatedBy: "u", CreatedAt: now, UpdatedAt: now}
	if err := normalizeBindingPolicy(&p); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.CreateKeyBindingPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := svc.store.GetKeyBindingPolicy(ctx, tenant, p.ID)
	if err != nil || got.LabelSelector["env"] != "prod" || got.Channels[0] != "kms-kmip" || got.SourceNetworks[0] != "10.0.0.0/8" ||
		got.WorkloadIdentities[0] != "spiffe://x/*" || got.AllKeys || got.Status != "active" || got.CreatedAt.IsZero() {
		t.Fatalf("read back: %+v %v", got, err)
	}
	if err := svc.checkKeyBindings(ctx, key, AccessActor{Authenticated: true, SourceIP: "10.1.1.1"}); err == nil {
		t.Fatal("a direct caller reached a KMIP-bound key")
	}
	got.AllKeys, got.LabelSelector, got.Status = true, map[string]string{}, "disabled"
	if err := svc.store.UpdateKeyBindingPolicy(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := svc.store.GetKeyBindingPolicy(ctx, tenant, p.ID); !again.AllKeys || again.Status != "disabled" {
		t.Fatalf("update: %+v", again)
	}
	if err := svc.store.DeleteKeyBindingPolicy(ctx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}
}

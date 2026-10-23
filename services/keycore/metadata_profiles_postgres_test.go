package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

// Metadata profiles on Postgres (CI integration-postgres): migration 036,
// the rules read back, a name unique per tenant, and a key refused or
// given its default label.
func TestMetadataProfilesPostgres(t *testing.T) {
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
	tenant := "t-meta-pg-" + strings.ToLower(newID("x")[2:10])
	now := time.Now().UTC().Truncate(time.Microsecond)
	p := MetadataProfile{ID: newID("mdp"), TenantID: tenant, Name: "pg", Purposes: []string{"encrypt"}, Status: "active",
		MetadataProfileRules: MetadataProfileRules{Labels: []MetadataLabelRule{{Key: "env", Required: true, Allowed: []string{"prod"}}, {Key: "tier", Default: "gold"}}},
		CreatedBy:            "u", UpdatedBy: "u", CreatedAt: now, UpdatedAt: now}
	if err := normalizeMetadataProfile(&p); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.CreateMetadataProfile(ctx, p); err != nil {
		t.Fatal(err)
	}
	dup := p
	dup.ID = newID("mdp")
	if err := svc.store.CreateMetadataProfile(ctx, dup); err == nil || !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Fatalf("duplicate name: %v", err)
	}
	got, err := svc.store.GetMetadataProfile(ctx, tenant, p.ID)
	if err != nil || len(got.Labels) != 2 || got.Labels[0].Allowed[0] != "prod" || got.Purposes[0] != "encrypt" || got.CreatedAt.IsZero() {
		t.Fatalf("read back: %+v %v", got, err)
	}
	var v *MetadataViolation
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: "bad", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "u"}); !errors.As(err, &v) {
		t.Fatalf("refusal: %v", err)
	}
	k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: "good", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Labels: map[string]string{"env": "prod"}, CreatedBy: "u"})
	if err != nil || k.Labels["tier"] != "gold" {
		t.Fatalf("create: %+v %v", k.Labels, err)
	}
	if err := svc.store.DeleteMetadataProfile(ctx, tenant, p.ID); err != nil {
		t.Fatal(err)
	}
}

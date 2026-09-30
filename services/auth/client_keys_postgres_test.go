package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Client key rotation, revocation and unbound-key retirement on real
// Postgres (CI integration-postgres): the tenant transactions and the
// RLS-enabled auth_api_keys table behave as the SQLite tests assume.
func TestClientKeyLifecyclePostgres(t *testing.T) {
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
	tenant := "t-ck-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := s.CreateTenant(ctx, Tenant{ID: tenant, Name: tenant, Status: "active"}); err != nil {
		t.Fatal(err)
	}
	reg := ClientRegistration{ID: "reg-" + tenant, TenantID: tenant, ClientName: "pipeline", ClientType: "service", InterfaceName: "rest", Status: "pending", RateLimit: 1000, AuthMode: "api_key"}
	if err := s.CreateClientRegistration(ctx, reg); err != nil {
		t.Fatal(err)
	}
	h1, h2 := []byte("pg-h1-"+tenant), []byte("pg-h2-"+tenant)
	if err := s.ActivateClientRegistration(ctx, tenant, reg.ID, APIKey{ID: "k1-" + tenant, ClientID: reg.ID, KeyHash: h1, KeyPrefix: "vk_1", Name: "client", Permissions: clientKeyPermissions}, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.ActivateClientRegistration(ctx, tenant, reg.ID, APIKey{ID: "kx-" + tenant, ClientID: reg.ID, KeyHash: []byte("x"), Name: "client"}, "admin", ""); !errors.Is(err, errClientState) {
		t.Fatalf("second activation: %v", err)
	}
	if err := s.RotateClientAPIKey(ctx, tenant, reg.ID, APIKey{ID: "k2-" + tenant, ClientID: reg.ID, KeyHash: h2, KeyPrefix: "vk_2", Name: "client", Permissions: clientKeyPermissions}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAPIKeyByHash(ctx, tenant, h1); !errors.Is(err, errNotFound) {
		t.Fatalf("old key survived rotation: %v", err)
	}
	if k, err := s.GetAPIKeyByHash(ctx, tenant, h2); err != nil || k.ClientID != reg.ID {
		t.Fatalf("rotated key: %+v %v", k, err)
	}
	if err := s.CreateUser(ctx, User{ID: "u-" + tenant, TenantID: tenant, Username: "u-" + tenant, Email: "u@example.com", Role: "tenant-admin", Status: "active", Password: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(ctx, APIKey{ID: "ku-" + tenant, TenantID: tenant, UserID: "u-" + tenant, KeyHash: []byte("pg-u-" + tenant), Name: "manual", Permissions: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteUnboundAPIKeys(ctx, tenant); err != nil || n != 1 {
		t.Fatalf("unbound retired=%d err=%v", n, err)
	}
	if err := s.RevokeClientRegistration(ctx, tenant, reg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAPIKeyByHash(ctx, tenant, h2); !errors.Is(err, errNotFound) {
		t.Fatalf("key survived revocation: %v", err)
	}
	if err := s.RotateClientAPIKey(ctx, tenant, reg.ID, APIKey{ID: "k3-" + tenant, KeyHash: []byte("h3")}); !errors.Is(err, errClientState) {
		t.Fatalf("rotating a revoked client: %v", err)
	}
}

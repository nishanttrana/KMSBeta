package main

import (
	"context"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

func newTestStore(t *testing.T) *SQLStore {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createSQLiteSchema(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return NewSQLStore(conn)
}

func createSQLiteSchema(conn *pkgdb.DB) error {
	sql := []string{
		`CREATE TABLE auth_tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE auth_tenant_roles (tenant_id TEXT NOT NULL, role_name TEXT NOT NULL, permissions BLOB NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(tenant_id, role_name));`,
		`CREATE TABLE auth_users (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, username TEXT NOT NULL, email TEXT NOT NULL, pwd_hash BLOB NOT NULL, totp_secret TEXT, role TEXT NOT NULL, status TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(tenant_id, username));`,
		`CREATE TABLE auth_client_registrations (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, client_name TEXT NOT NULL, client_type TEXT NOT NULL, description TEXT, contact_email TEXT NOT NULL, requested_role TEXT NOT NULL, status TEXT NOT NULL, api_key_hash BLOB, api_key_prefix TEXT, approved_by BLOB, approval_id TEXT, ip_whitelist BLOB, rate_limit INTEGER DEFAULT 1000, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, approved_at TIMESTAMP, expires_at TIMESTAMP, last_used TIMESTAMP);`,
		`CREATE TABLE auth_api_keys (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT, client_id TEXT, key_hash BLOB NOT NULL, name TEXT NOT NULL, permissions BLOB NOT NULL, expires_at TIMESTAMP, last_used TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE auth_sessions (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, token_hash BLOB NOT NULL, ip_address TEXT, user_agent TEXT, expires_at TIMESTAMP NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE auth_password_policies (tenant_id TEXT PRIMARY KEY, min_length INTEGER NOT NULL DEFAULT 12, max_length INTEGER NOT NULL DEFAULT 128, require_upper INTEGER NOT NULL DEFAULT 1, require_lower INTEGER NOT NULL DEFAULT 1, require_digit INTEGER NOT NULL DEFAULT 1, require_special INTEGER NOT NULL DEFAULT 1, require_no_whitespace INTEGER NOT NULL DEFAULT 1, deny_username INTEGER NOT NULL DEFAULT 1, deny_email_local_part INTEGER NOT NULL DEFAULT 1, min_unique_chars INTEGER NOT NULL DEFAULT 6, updated_by TEXT NOT NULL DEFAULT 'system', updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`,
	}
	for _, q := range sql {
		if _, err := conn.SQL().Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func TestSQLStoreUserAndRoleFlow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, Tenant{ID: "t1", Name: "Tenant1", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTenantRole(ctx, TenantRole{TenantID: "t1", RoleName: "tenant-admin", Permissions: []string{"auth.user.write", "auth.client.activate"}}); err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword("secret")
	if err := s.CreateUser(ctx, User{
		ID: "u1", TenantID: "t1", Username: "alice", Email: "a@example.com",
		Password: hash, Role: "tenant-admin", Status: "active", MustChangePassword: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetUserByUsername(ctx, "t1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.TenantID != "t1" || got.Role != "tenant-admin" {
		t.Fatalf("unexpected user %+v", got)
	}
	if !got.MustChangePassword {
		t.Fatal("expected must_change_password=true")
	}
	byID, err := s.GetUserByID(ctx, "t1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if byID.Username != "alice" {
		t.Fatalf("unexpected user by id %+v", byID)
	}
	newHash, _ := HashPassword("new-secret")
	if err := s.UpdateUserPassword(ctx, "t1", "u1", newHash, false); err != nil {
		t.Fatal(err)
	}
	updated, err := s.GetUserByID(ctx, "t1", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.MustChangePassword {
		t.Fatal("expected must_change_password=false")
	}
	if !VerifyPassword(updated.Password, "new-secret") {
		t.Fatal("updated password hash mismatch")
	}
	perms, err := s.GetRolePermissions(ctx, "t1", "tenant-admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(perms) == 0 {
		t.Fatal("expected permissions")
	}
}

func TestSQLStoreClientActivationRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, Tenant{ID: "t2", Name: "Tenant2", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	reg := ClientRegistration{
		ID: "reg1", TenantID: "t2", ClientName: "svc", ClientType: "service",
		ContactEmail: "ops@example.com", RequestedRole: "app-service", Status: "pending", RateLimit: 1000,
	}
	if err := s.CreateClientRegistration(ctx, reg); err != nil {
		t.Fatal(err)
	}
	key := APIKey{
		ID: "k1", TenantID: "t2", ClientID: reg.ID, KeyHash: []byte("hash"), KeyPrefix: "vk_test",
		Name: "client:svc", Permissions: []string{"kms.read"},
	}
	if err := s.ActivateClientRegistration(ctx, "t2", reg.ID, key, "admin", "appr-1"); err != nil {
		t.Fatal(err)
	}
	out, err := s.GetClientRegistration(ctx, "t2", reg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "approved" {
		t.Fatalf("status=%s want approved", out.Status)
	}
	if out.APIKeyPrefix != key.KeyPrefix {
		t.Fatalf("prefix=%s want %s", out.APIKeyPrefix, key.KeyPrefix)
	}
	if err := s.RotateClientAPIKey(ctx, "t2", reg.ID, []byte("h2"), "vk_new"); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeClientRegistration(ctx, "t2", reg.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreSessionAndAPIKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, Tenant{ID: "t3", Name: "Tenant3", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAPIKey(ctx, APIKey{
		ID: "k1", TenantID: "t3", Name: "manual", KeyHash: []byte("hash"), Permissions: []string{"*"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAPIKey(ctx, "t3", "k1"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, Session{
		ID: "s1", TenantID: "t3", UserID: "u1", TokenHash: []byte("th"), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "t3", "s1"); err != nil {
		t.Fatal(err)
	}
}

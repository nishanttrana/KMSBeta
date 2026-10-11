package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

// The credential store on real Postgres (CI integration-postgres):
// migration 010 (re-runnable), the nullable dates, what a changed secret
// resets, test results and reminders.
func TestCredentialStorePostgres(t *testing.T) {
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
	for i := 0; i < 2; i++ {
		if err := conn.RunMigrations(ctx, "migrations"); err != nil {
			t.Fatalf("migrations (pass %d): %v", i+1, err)
		}
	}
	db := conn.SQL()
	tenant := "t-cred-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM compliance_playbook_connections WHERE tenant_id=$1`, tenant)
	})
	store := NewSQLStore(conn)
	sealed := &pkgcrypto.EnvelopeCiphertext{Ciphertext: []byte("c"), DataIV: []byte("i"), WrappedDEK: []byte("w"), WrappedDEKIV: []byte("v")}

	// A row as 006 wrote it, before 010 added its columns' values.
	if _, err := db.Exec(`INSERT INTO compliance_playbook_connections (id, tenant_id, name, type, creds_ciphertext, creds_data_iv, creds_wrapped_dek, creds_wrapped_dek_iv)
		VALUES ('pbconn-old', $1, 'old', 'slack', 'c', 'i', 'w', 'v')`, tenant); err != nil {
		t.Fatal(err)
	}
	old, err := store.GetConnection(ctx, tenant, "pbconn-old")
	if err != nil || old.ExpiresAt != nil || old.LastTestedAt != nil || old.RotateAfterDays != 0 || len(old.Attributes) != 0 || len(old.Notified) != 0 {
		t.Fatalf("pre-010 row read as %+v (%v)", old, err)
	}

	expires := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	c, err := store.CreateConnection(ctx, Connection{ID: "pbconn-hsm", TenantID: tenant, Name: "Luna", Type: "pkcs11_hsm", Endpoint: "token prod",
		FieldSet: []string{"library_path", "pin"}, Attributes: map[string]string{"topology": "ha_group"}, ExpiresAt: &expires, RotateAfterDays: 90, Sealed: sealed})
	if err != nil {
		t.Fatal(err)
	}
	if c.Attributes["topology"] != "ha_group" || c.ExpiresAt == nil || !c.ExpiresAt.Equal(expires) || c.RotateAfterDays != 90 || c.CredentialsChangedAt.IsZero() || c.LastTestedAt != nil {
		t.Fatalf("created: %+v", c)
	}
	if err := store.RecordConnectionTest(ctx, tenant, c.ID, false, strings.Repeat("x", 900)); err != nil {
		t.Fatal(err)
	}
	if err := store.SetConnectionNotified(ctx, tenant, c.ID, []string{remindExpiring7}); err != nil {
		t.Fatal(err)
	}
	c, _ = store.GetConnection(ctx, tenant, c.ID)
	if c.LastTestedAt == nil || c.LastTestOK || len(c.LastTestError) != 500 || len(c.Notified) != 1 {
		t.Fatalf("after a failed test: tested=%v ok=%v err=%d notified=%v", c.LastTestedAt, c.LastTestOK, len(c.LastTestError), c.Notified)
	}
	changedAt := c.CredentialsChangedAt
	// Renaming keeps the age, the test result and the reminders.
	c.Name, c.Sealed = "Luna HA", sealed
	if c, err = store.UpdateConnection(ctx, c, false, false); err != nil || !c.CredentialsChangedAt.Equal(changedAt) || c.LastTestedAt == nil || len(c.Notified) != 1 || c.Name != "Luna HA" {
		t.Fatalf("rename: %+v %v", c, err)
	}
	// New dates clear the reminders only.
	c.ExpiresAt, c.Sealed = nil, sealed
	if c, err = store.UpdateConnection(ctx, c, false, true); err != nil || c.ExpiresAt != nil || len(c.Notified) != 0 || c.LastTestedAt == nil {
		t.Fatalf("dates changed: %+v %v", c, err)
	}
	// A new secret restarts its age and clears the test result.
	_ = store.SetConnectionNotified(ctx, tenant, c.ID, []string{remindRotation})
	time.Sleep(1100 * time.Millisecond)
	c.Sealed = sealed
	if c, err = store.UpdateConnection(ctx, c, true, false); err != nil || !c.CredentialsChangedAt.After(changedAt) || c.LastTestedAt != nil || c.LastTestError != "" || len(c.Notified) != 0 {
		t.Fatalf("secret changed: %+v %v", c, err)
	}
	all, err := store.ListAllConnections(ctx)
	if err != nil || len(all) < 2 {
		t.Fatalf("list all: %d %v", len(all), err)
	}

	// A mail relay's allowance comes from the tenant's approved ranges.
	if err := store.CreatePrivateEndpoint(ctx, PrivateEndpoint{ID: "pvt-" + tenant, TenantID: tenant, CIDR: "10.20.0.0/16", CreatedBy: "root-admin"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = store.DeletePrivateEndpoint(ctx, "pvt-"+tenant) })
	if a := approvedAllow(ctx, store, tenant, "smtp"); len(a) != 1 || a.ValidateHost("10.20.1.1") != nil || a.ValidateHost("10.21.1.1") == nil {
		t.Fatalf("mail allowance from the store: %v", a)
	}
	if a := approvedAllow(ctx, store, tenant, "webhook"); len(a) != 1 {
		t.Fatalf("webhook allowance from the store: %v", a)
	}
	if a := approvedAllow(ctx, store, tenant, "aws"); len(a) != 0 {
		t.Fatalf("a cloud account was given a private allowance: %v", a)
	}
}

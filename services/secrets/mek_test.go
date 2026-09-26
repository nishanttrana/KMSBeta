package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/route/routetest"
)

// keycoreStandIn is keycore's system key for kms-secrets: one version.
type keycoreStandIn struct{ key []byte }

func (k keycoreStandIn) EnsureKey(context.Context) (string, int, error) { return "key_sys_secrets", 1, nil }
func (k keycoreStandIn) Derive(context.Context, string, int) ([]byte, int, error) {
	return k.key, 1, nil
}

func execFile(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	ddl, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range strings.Split(string(ddl), ";") {
		if strings.TrimSpace(strings.Join(nonComment(stmt), "")) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

func nonComment(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "--") {
			out = append(out, l)
		}
	}
	return out
}

// The upgrade from a release that stored secrets under the public dev key:
// every value stays readable, none opens with the public key, each secret is
// listed as exposed until its value is rotated, and that is audited.
func exerciseUpgrade(t *testing.T, conn *pkgdb.DB) {
	ctx := context.Background()
	store := NewSQLStore(conn)
	dev := mek.Catalog["secrets"].LegacyKeysFromEnv()[0]
	if dev.Name != "dev_mek" || !dev.Public {
		t.Fatalf("first legacy key is %+v", dev)
	}
	old := NewService(store, dev.Key)
	a, err := old.CreateSecret(ctx, CreateSecretRequest{TenantID: "t1", Name: "db", SecretType: "password", Value: "hunter2", CreatedBy: "x"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := old.CreateSecret(ctx, CreateSecretRequest{TenantID: "t1", Name: "api", SecretType: "api_key", Value: "k-1", CreatedBy: "x"})
	if err != nil {
		t.Fatal(err)
	}

	kc := keycoreStandIn{key: mustRandom(t)}
	audit := &routetest.Recorder{}
	keyring, err := mek.Open(ctx, mek.Options{Tables: mek.Catalog["secrets"], Source: kc, DB: conn.SQL(), Audit: audit, Logf: t.Logf})
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	svc := NewService(store, keyring.Current())
	for id, want := range map[string]string{a.ID: "hunter2", b.ID: "k-1"} {
		if v, err := svc.GetSecretValue(ctx, "t1", id, "raw"); err != nil || v.Value != want {
			t.Fatalf("after upgrade %s = %q %v", id, v.Value, err)
		}
		if _, err := old.GetSecretValue(ctx, "t1", id, "raw"); err == nil {
			t.Fatal("the public dev key still opens a stored secret")
		}
	}
	var sawEvent bool
	for _, e := range audit.Events() {
		sawEvent = sawEvent || (e.Action == "dev_mek_rewrapped" && e.Event.TenantID == "t1" && e.Event.Details["item_count"] == 2)
	}
	if !sawEvent {
		t.Fatalf("dev_mek_rewrapped not emitted: %+v", audit.Events())
	}

	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil, keyring)
	admin := tenantAdmin("t1")
	rr := serveAs(h, admin, httptest.NewRequest(http.MethodGet, "/mek/exposure", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"open":2`) {
		t.Fatalf("exposure list: %d %s", rr.Code, rr.Body)
	}
	// Rotating a value closes its entry; deleting the other closes that one.
	rr = serveAs(h, admin, httptest.NewRequest(http.MethodPost, "/secrets/"+a.ID+"/rotate", strings.NewReader(`{"value":"n3w"}`)))
	if rr.Code != http.StatusOK || rec.Last(t).Event.Details["exposure_remediated"] != true {
		t.Fatalf("rotate: %d %s %+v", rr.Code, rr.Body, rec.Last(t))
	}
	if rr := serveAs(h, admin, httptest.NewRequest(http.MethodDelete, "/secrets/"+b.ID, nil)); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if open, _ := keyring.Exposures(ctx, "t1", true); len(open) != 0 {
		t.Fatalf("still exposed: %+v", open)
	}
	all, _ := keyring.Exposures(ctx, "t1", false)
	for _, e := range all {
		if e.RemediatedAt == nil || (e.Remediation != "rotated" && e.Remediation != "deleted") || e.RemediatedBy != "u-t1" {
			t.Fatalf("remediation record %+v", e)
		}
	}
}

func mustRandom(t *testing.T) []byte {
	k, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestUpgradeMovesSecretsOffPublicKey(t *testing.T) {
	_, store := newSecretsService(t)
	execFile(t, store.db.SQL(), "migrations/003_mek_state.sql")
	exerciseUpgrade(t, store.db)
}

func TestUpgradeMovesSecretsOffPublicKeyPostgres(t *testing.T) {
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
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE secrets, secret_values, secret_audit_log, secrets_mek_state, secrets_mek_exposure`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	exerciseUpgrade(t, conn)
}

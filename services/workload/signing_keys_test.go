package main

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/mek"
	"vecta-kms/pkg/mek/mektest"
	"vecta-kms/pkg/route/routetest"
)

// The tenant signing keys at rest: sealed on every write, earlier plaintext
// rows sealed by the primary only (and recorded as exposed), no plaintext
// PEM left in the table, envelopes bound to their tenant, rotation closing
// the exposure, and a failed seal refused and audited. Run on SQLite always
// and on real Postgres when VECTA_TEST_POSTGRES_DSN is set (CI
// integration-postgres).
func TestSigningKeysSealedAtRestSQLite(t *testing.T) {
	open := func(t *testing.T) *pkgdb.DB {
		conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	runSigningKeysSuite(t, open)
}

func TestSigningKeysSealedAtRestPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	open := func(t *testing.T) *pkgdb.DB {
		conn, err := pkgdb.Open(context.Background(), pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	runSigningKeysSuite(t, open)
}

func runSigningKeysSuite(t *testing.T, open func(*testing.T) *pkgdb.DB) {
	ctx := context.Background()
	conn := open(t)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	db := conn.SQL()
	// The database may be shared with earlier runs: start from a fresh pin
	// and clean up this run's tenants.
	_, _ = db.Exec(`DELETE FROM workload_mek_state`)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	legacy, fresh, other := "t-wl-legacy-"+suffix, "t-wl-new-"+suffix, "t-wl-other-"+suffix
	t.Cleanup(func() {
		for _, tn := range []string{legacy, fresh, other} {
			_, _ = db.Exec(`DELETE FROM workload_identity_settings WHERE tenant_id = $1`, tn)
			_, _ = db.Exec(`DELETE FROM workload_mek_exposure WHERE tenant_id = $1`, tn)
		}
	})

	kc := mektest.NewKeycore(t)
	rec := &routetest.Recorder{}
	openKeys := func(c *pkgdb.DB) *mek.Keyring {
		k, err := mek.Open(ctx, mek.Options{Tables: mek.Catalog["workload"], Source: kc, DB: c.SQL(), Audit: rec, Logf: t.Logf})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	keys := openKeys(conn)
	store := NewSQLStore(conn, keys)
	svc := NewService(store, nil, nil)
	svc.keys = keys

	// A row as an earlier release wrote it: private keys as plaintext PEM.
	caCert, caKey, jwtPriv, jwtPub, kid, jwks, err := generateSigningMaterial("legacy.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO workload_identity_settings
		(tenant_id, trust_domain, local_bundle_jwks, local_ca_cert_pem, local_ca_key_pem, jwt_signer_private_pem, jwt_signer_public_pem, jwt_signer_kid)
		VALUES ($1, 'legacy.example', $2, $3, $4, $5, $6, $7)`, legacy, jwks, caCert, caKey, jwtPriv, jwtPub, kid); err != nil {
		t.Fatal(err)
	}
	// Not sealed yet: still usable (a cluster member reads it as is).
	if got, err := store.GetSettings(ctx, legacy); err != nil || got.LocalCAKeyPEM != caKey || got.JWTSignerPrivatePEM != jwtPriv {
		t.Fatalf("unsealed legacy row not readable: %v", err)
	}

	// A member never writes the replicated table.
	if n, err := store.SealPlaintextSigningKeys(ctx, func(context.Context) bool { return false }, rec); err != nil || n != 0 {
		t.Fatalf("member sealed: %d %v", n, err)
	}
	if plaintextFor(t, db, legacy) == 0 {
		t.Fatal("a member changed the row")
	}

	// A failed seal is refused and audited, and leaves the row as it was:
	// here the exposure register can't be written.
	broken := open(t)
	if err := broken.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatal(err)
	}
	brokenKeys := openKeys(broken)
	_ = broken.Close()
	rec.Reset()
	if _, err := NewSQLStore(conn, brokenKeys).SealPlaintextSigningKeys(ctx, func(context.Context) bool { return true }, rec); err == nil {
		t.Fatal("seal without an exposure record succeeded")
	}
	if !recorded(rec, "mek_signing_keys_seal_refused", legacy, "refused") {
		t.Fatalf("seal refusal not audited: %+v", rec.Events())
	}
	if plaintextFor(t, db, legacy) == 0 {
		t.Fatal("a refused seal changed the row")
	}

	// The primary seals it, records the exposure first, and empties the
	// plaintext columns.
	rec.Reset()
	if n, err := store.SealPlaintextSigningKeys(ctx, func(context.Context) bool { return true }, rec); err != nil || n < 1 {
		t.Fatalf("seal: %d %v", n, err)
	}
	if !recorded(rec, "mek_exposure_recorded", legacy, "success") || !recorded(rec, "mek_signing_keys_sealed", legacy, "success") {
		t.Fatalf("seal not audited: %+v", rec.Events())
	}
	if openExposures(t, keys, legacy) != 1 {
		t.Fatal("sealed plaintext row not in the exposure register")
	}
	got, err := store.GetSettings(ctx, legacy)
	if err != nil || got.LocalCAKeyPEM != caKey || got.JWTSignerPrivatePEM != jwtPriv {
		t.Fatalf("sealed keys don't open to the originals: %v", err)
	}

	// A new tenant is sealed from its first write.
	if _, err := svc.GetSettings(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	for _, tn := range []string{legacy, fresh} {
		if plaintextFor(t, db, tn) != 0 {
			t.Fatalf("%s: plaintext private key left in the table", tn)
		}
		var sealed int
		_ = db.QueryRow(`SELECT COUNT(*) FROM workload_identity_settings WHERE tenant_id = $1 AND signing_wrapped_dek IS NOT NULL AND signing_ciphertext IS NOT NULL`, tn).Scan(&sealed)
		if sealed != 1 {
			t.Fatalf("%s: no sealed envelope", tn)
		}
		var ct []byte
		_ = db.QueryRow(`SELECT signing_ciphertext FROM workload_identity_settings WHERE tenant_id = $1`, tn).Scan(&ct)
		if strings.Contains(string(ct), "PRIVATE KEY") {
			t.Fatalf("%s: envelope holds PEM in the clear", tn)
		}
	}

	// An envelope copied onto another tenant's row doesn't open there.
	if _, err := svc.GetSettings(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE workload_identity_settings SET
		signing_ciphertext = (SELECT signing_ciphertext FROM workload_identity_settings WHERE tenant_id = $1),
		signing_data_iv = (SELECT signing_data_iv FROM workload_identity_settings WHERE tenant_id = $1),
		signing_wrapped_dek = (SELECT signing_wrapped_dek FROM workload_identity_settings WHERE tenant_id = $1),
		signing_wrapped_dek_iv = (SELECT signing_wrapped_dek_iv FROM workload_identity_settings WHERE tenant_id = $1)
		WHERE tenant_id = $2`, legacy, other); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSettings(ctx, other); err == nil {
		t.Fatal("another tenant's signing keys opened")
	}

	// Rotating replaces both keys and closes the exposure.
	rec.Reset()
	actx := pkgauth.ContextWithClaims(ctx, &pkgauth.Claims{UserID: "admin", TenantID: legacy})
	if _, err := svc.RotateSigningKeys(actx, legacy, "admin"); err != nil {
		t.Fatal(err)
	}
	got, err = store.GetSettings(ctx, legacy)
	if err != nil || got.LocalCAKeyPEM == caKey || got.JWTSignerPrivatePEM == jwtPriv || got.JWTSignerKeyID == kid {
		t.Fatalf("rotation kept the old keys: %v", err)
	}
	if openExposures(t, keys, legacy) != 0 || !recorded(rec, "mek_exposure_remediated", legacy, "success") {
		t.Fatal("rotation did not close the exposure")
	}
}

func plaintextFor(t *testing.T, db *sql.DB, tenant string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM workload_identity_settings WHERE tenant_id = $1 AND (local_ca_key_pem <> '' OR jwt_signer_private_pem <> '')`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func openExposures(t *testing.T, k *mek.Keyring, tenant string) int {
	t.Helper()
	items, err := k.Exposures(context.Background(), tenant, true)
	if err != nil {
		t.Fatal(err)
	}
	return len(items)
}

func recorded(rec *routetest.Recorder, action, tenant, result string) bool {
	for _, e := range rec.Events() {
		if e.Action == action && e.Event.TenantID == tenant && e.Event.Result == result {
			return true
		}
	}
	return false
}

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/credstore"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

// Dynamic database credentials against a real PostgreSQL that checks
// passwords (scram-sha-256): each issued login is used, renewal moves its
// expiry, and revocation and expiry really drop it. The test server has no
// TLS, so connectDB is replaced to dial it in plaintext with the
// credential's own fields; the TLS settings are proven in dbengine_test.go.

type testCreds map[string]credstore.Credential

func (c testCreds) Resolve(_ context.Context, _ string, id string) (credstore.Credential, error) {
	if v, ok := c[id]; ok {
		return v, nil
	}
	return credstore.Credential{}, credstore.ErrNotFound
}
func (testCreds) Import(context.Context, string, string, string, string, map[string]string, bool) (string, error) {
	return "", errors.New("unused")
}
func (testCreds) ReportTest(context.Context, string, string, error) error { return nil }

func TestDynamicDatabaseCredentialsPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminPass, _ := u.User.Password()
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "5432"
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx) //nolint:errcheck
	target := fmt.Sprintf("dbengine_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+target+" WITH (FORCE)")
	})
	targetDSN := func(user, pass string) string {
		return (&url.URL{Scheme: "postgres", User: url.UserPassword(user, pass), Host: host + ":" + port, Path: "/" + target, RawQuery: "sslmode=disable"}).String()
	}
	tadmin, err := pgx.Connect(ctx, targetDSN(u.User.Username(), adminPass))
	if err != nil {
		t.Fatal(err)
	}
	defer tadmin.Close(ctx) //nolint:errcheck
	if _, err := tadmin.Exec(ctx, "CREATE TABLE orders (id int); INSERT INTO orders VALUES (1), (2)"); err != nil {
		t.Fatal(err)
	}

	old := connectDB
	connectDB = func(ctx context.Context, t dbTarget) (*pgx.Conn, error) {
		return pgx.Connect(ctx, (&url.URL{Scheme: "postgres", User: url.UserPassword(t.User, t.Password), Host: t.Host + ":" + t.Port, Path: "/" + t.Database, RawQuery: "sslmode=disable"}).String())
	}
	t.Cleanup(func() { connectDB = old })

	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE secret_db_roles, secret_db_leases`); err != nil {
		t.Fatal(err)
	}
	svc := NewService(NewSQLStore(conn), []byte("0123456789ABCDEF0123456789ABCDEF"))
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil, nil)
	creds := testCreds{
		"pbconn_db":      {ID: "pbconn_db", Type: "database", Fields: map[string]string{"host": host, "port": port, "database": target, "username": u.User.Username(), "password": adminPass}},
		"pbconn_gone_db": {ID: "pbconn_gone_db", Type: "database", Fields: map[string]string{"host": host, "port": port, "database": "no_such_db", "username": "nobody", "password": "x"}},
	}
	h.creds = creds
	admins := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Permissions: []string{"*"}}
	app := &pkgauth.Claims{UserID: "app", TenantID: "t1", Permissions: []string{permDBCreds, permDBRead}}
	do := func(who *pkgauth.Claims, method, path, body string) (int, map[string]interface{}) {
		t.Helper()
		return call(t, h, who, method, path, body)
	}
	canLogin := func(user, pass string) error {
		c, err := pgx.Connect(ctx, targetDSN(user, pass))
		if err != nil {
			return err
		}
		defer c.Close(ctx) //nolint:errcheck
		var n int
		return c.QueryRow(ctx, "SELECT count(*) FROM orders").Scan(&n)
	}
	roleExists := func(user string) bool {
		var n int
		_ = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname = $1", user).Scan(&n)
		return n == 1
	}

	// A role: refused without credential use, with a bad template, an
	// unreachable database or a TTL out of range; accepted with defaults.
	if code, _ := do(&pkgauth.Claims{UserID: "dba", TenantID: "t1", Permissions: []string{permDBAdmin}}, "PUT", "/secrets/database/roles/readers", `{"connection_id":"pbconn_db","default_ttl_seconds":3600,"max_ttl_seconds":7200}`); code != http.StatusForbidden {
		t.Fatalf("a role attached a credential without compliance.connection.use: %d", code)
	}
	for name, body := range map[string]string{
		"bad template": `{"connection_id":"pbconn_db","creation_statements":["CREATE ROLE {{name}} PASSWORD {{password}} {{oops}}"],"default_ttl_seconds":3600,"max_ttl_seconds":7200}`,
		"unreachable":  `{"connection_id":"pbconn_gone_db","default_ttl_seconds":3600,"max_ttl_seconds":7200}`,
		"ttl":          `{"connection_id":"pbconn_db","default_ttl_seconds":10,"max_ttl_seconds":7200}`,
	} {
		if code, _ := do(admins, "PUT", "/secrets/database/roles/readers", body); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, code)
		}
	}
	if code, out := do(admins, "PUT", "/secrets/database/roles/readers", `{"connection_id":"pbconn_db","default_ttl_seconds":3600,"max_ttl_seconds":7200}`); code != http.StatusOK {
		t.Fatalf("role: %d %v", code, out)
	}

	// Issue: a login that works on the database, with its password.
	code, out := do(app, "POST", "/secrets/database/roles/readers/creds", `{"ttl_seconds":600}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %v", code, out)
	}
	user, pass := out["username"].(string), out["password"].(string)
	leaseID := out["lease"].(map[string]interface{})["id"].(string)
	if err := canLogin(user, pass); err != nil {
		t.Fatalf("the issued login does not work: %v", err)
	}
	if err := canLogin(user, pass+"x"); err == nil {
		t.Fatal("a wrong password logged in: the server is not checking passwords")
	}
	if e := rec.Last(t); e.Action != "database_credentials_issued" || e.Event.Result != "success" || strings.Contains(fmt.Sprint(e.Event.Details), pass) {
		t.Fatalf("issue event %+v", e.Event)
	}

	// Renew moves the login's own expiry, capped by the role's maximum.
	var before, after time.Time
	_ = admin.QueryRow(ctx, "SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1", user).Scan(&before)
	if code, out := do(app, "POST", "/secrets/database/leases/"+leaseID+"/renew", `{"increment_seconds":7000}`); code != http.StatusOK {
		t.Fatalf("renew: %d %v", code, out)
	}
	_ = admin.QueryRow(ctx, "SELECT rolvaliduntil FROM pg_roles WHERE rolname = $1", user).Scan(&after)
	if !after.After(before.Add(time.Hour)) {
		t.Fatalf("valid until %v -> %v", before, after)
	}
	if code, _ := do(app, "POST", "/secrets/database/leases/"+leaseID+"/renew", `{"increment_seconds":7000}`); code != http.StatusConflict {
		t.Fatalf("renewing past the maximum: %d", code)
	}

	// A role with live leases can't be deleted.
	if code, _ := do(admins, "DELETE", "/secrets/database/roles/readers", ""); code != http.StatusConflict {
		t.Fatalf("delete with leases: %d", code)
	}

	// Revoke drops the login.
	if code, out := do(app, "POST", "/secrets/database/leases/"+leaseID+"/revoke", ""); code != http.StatusOK || out["lease"].(map[string]interface{})["state"] != "revoked" {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if roleExists(user) || canLogin(user, pass) == nil {
		t.Fatal("the revoked login still exists")
	}

	// Vault form: GET creds, then revoke by lease_id.
	code, vout := do(app, "GET", "/v1/database/creds/readers", "")
	if code != http.StatusOK {
		t.Fatalf("vault creds: %d %v", code, vout)
	}
	vdata := vout["data"].(map[string]interface{})
	if err := canLogin(vdata["username"].(string), vdata["password"].(string)); err != nil || !strings.HasPrefix(vout["lease_id"].(string), "database/creds/readers/dbl_") {
		t.Fatalf("vault login: %v %v", err, vout)
	}
	if code, _ := do(app, "PUT", "/v1/sys/leases/revoke", `{"lease_id":"`+vout["lease_id"].(string)+`"}`); code != http.StatusNoContent {
		t.Fatalf("vault revoke: %d", code)
	}
	if roleExists(vdata["username"].(string)) {
		t.Fatal("vault revoke left the login")
	}

	// Expiry: the sweep drops a lapsed login and records it.
	code, out = do(app, "POST", "/secrets/database/roles/readers/creds", "")
	if code != http.StatusOK {
		t.Fatalf("issue 2: %d %v", code, out)
	}
	user2 := out["username"].(string)
	id2 := out["lease"].(map[string]interface{})["id"].(string)
	if n := h.sweepDBLeases(ctx, time.Now().Add(2*time.Hour)); n != 1 || roleExists(user2) {
		t.Fatalf("sweep ended %d, login left %v", n, roleExists(user2))
	}
	l2, _ := svc.store.GetDBLease(ctx, "t1", id2)
	if l2.State != "expired" || rec.Last(t).Action != "database_lease_expired" {
		t.Fatalf("lease %+v event %s", l2, rec.Last(t).Action)
	}

	// A revocation that fails is recorded, audited and retried.
	code, out = do(app, "POST", "/secrets/database/roles/readers/creds", "")
	if code != http.StatusOK {
		t.Fatalf("issue 3: %d", code)
	}
	user3, id3 := out["username"].(string), out["lease"].(map[string]interface{})["id"].(string)
	creds["pbconn_db_saved"] = creds["pbconn_db"]
	delete(creds, "pbconn_db")
	if n := h.sweepDBLeases(ctx, time.Now().Add(2*time.Hour)); n != 0 {
		t.Fatalf("sweep without the credential ended %d", n)
	}
	if l3, _ := svc.store.GetDBLease(ctx, "t1", id3); l3.State != "revoke_failed" || l3.LastError == "" || rec.Last(t).Action != "database_lease_revoke_failed" {
		t.Fatalf("failed revocation %+v %s", l3, rec.Last(t).Action)
	}
	creds["pbconn_db"] = creds["pbconn_db_saved"]
	if n := h.sweepDBLeases(ctx, time.Now().Add(2*time.Hour)); n != 1 || roleExists(user3) {
		t.Fatalf("retry ended %d, login left %v", n, roleExists(user3))
	}

	// Another tenant sees none of it.
	other := &pkgauth.Claims{UserID: "eve", TenantID: "t2", Permissions: []string{"*"}}
	if code, out := do(other, "GET", "/secrets/database/leases", ""); code != http.StatusOK || len(out["items"].([]interface{})) != 0 {
		t.Fatalf("tenant t2 sees leases: %d %v", code, out)
	}
	if code, _ := do(other, "POST", "/secrets/database/roles/readers/creds", ""); code != http.StatusNotFound {
		t.Fatalf("tenant t2 issued from t1's role: %d", code)
	}
	if code, _ := do(&pkgauth.Claims{UserID: "ro", TenantID: "t1", Permissions: []string{permDBRead}}, "POST", "/secrets/database/roles/readers/creds", ""); code != http.StatusForbidden {
		t.Fatalf("a reader issued credentials: %d", code)
	}
}

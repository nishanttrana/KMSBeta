package mek

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// fakeKeycore holds versioned keys like keycore's system key.
type fakeKeycore struct {
	keyID    string
	versions map[int][]byte
	latest   int
	fail     error
}

func newFakeKeycore(t *testing.T) *fakeKeycore {
	return &fakeKeycore{keyID: "key_sys", versions: map[int][]byte{1: rnd(t)}, latest: 1}
}

func (f *fakeKeycore) rotate(t *testing.T) {
	f.latest++
	f.versions[f.latest] = rnd(t)
}

func (f *fakeKeycore) EnsureKey(context.Context) (string, int, error) {
	return f.keyID, f.latest, f.fail
}

func (f *fakeKeycore) Derive(_ context.Context, keyID string, v int) ([]byte, int, error) {
	if f.fail != nil {
		return nil, 0, f.fail
	}
	if v == 0 {
		v = f.latest
	}
	k, ok := f.versions[v]
	if !ok || keyID != f.keyID {
		return nil, 0, errors.New("no such key version")
	}
	return k, v, nil
}

func rnd(t testing.TB) []byte {
	k, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var testTables = ServiceTables{
	Service: "demo", ClientID: "kms-demo", StateTable: "mektest_state", ExposureTable: "mektest_exposure",
	Tables: []Table{
		{Name: "mektest_values", Keys: []string{"tenant_id", "item_id", "version"}, Tenant: "tenant_id", Item: "item_id",
			ItemType: "thing", WrappedDEK: "wrapped_dek", WrappedIV: "wrapped_iv"},
		{Name: "mektest_text", Keys: []string{"tenant_id", "id"}, Tenant: "tenant_id", Item: "id",
			ItemType: "text_thing", WrappedDEK: "dek", WrappedIV: "iv", Base64: true, Where: "kind = 'legacy'"},
	},
}

func setupDB(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, s := range []string{
		`DROP TABLE IF EXISTS mektest_values`, `DROP TABLE IF EXISTS mektest_text`,
		`DROP TABLE IF EXISTS mektest_state`, `DROP TABLE IF EXISTS mektest_exposure`,
		`CREATE TABLE mektest_values (tenant_id TEXT NOT NULL, item_id TEXT NOT NULL, version INTEGER NOT NULL,
			wrapped_iv BYTEA NOT NULL, wrapped_dek BYTEA NOT NULL, ciphertext BYTEA NOT NULL, data_iv BYTEA NOT NULL,
			PRIMARY KEY (tenant_id, item_id, version))`,
		`CREATE TABLE mektest_text (tenant_id TEXT NOT NULL, id TEXT NOT NULL, kind TEXT NOT NULL,
			iv TEXT NOT NULL, dek TEXT NOT NULL, ciphertext TEXT NOT NULL, data_iv TEXT NOT NULL, PRIMARY KEY (tenant_id, id))`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	for _, s := range strings.Split(SchemaSQL(testTables), ";") {
		if strings.TrimSpace(s) != "" {
			if _, err := db.Exec(s); err != nil {
				t.Fatalf("schema: %v", err)
			}
		}
	}
}

func put(t *testing.T, db *sql.DB, key []byte, tenant, item string, version int, value string) {
	t.Helper()
	env, err := pkgcrypto.EncryptEnvelope(key, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mektest_values VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenant, item, version, env.WrappedDEKIV, env.WrappedDEK, env.Ciphertext, env.DataIV); err != nil {
		t.Fatal(err)
	}
}

func putText(t *testing.T, db *sql.DB, key []byte, tenant, id, kind, value string) {
	t.Helper()
	env, err := pkgcrypto.EncryptEnvelope(key, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mektest_text VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenant, id, kind, b64(env.WrappedDEKIV), b64(env.WrappedDEK), b64(env.Ciphertext), b64(env.DataIV)); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, db *sql.DB, key []byte, tenant, item string, version int) (string, error) {
	t.Helper()
	var env pkgcrypto.EnvelopeCiphertext
	if err := db.QueryRow(`SELECT wrapped_iv, wrapped_dek, ciphertext, data_iv FROM mektest_values WHERE tenant_id=$1 AND item_id=$2 AND version=$3`, tenant, item, version).
		Scan(&env.WrappedDEKIV, &env.WrappedDEK, &env.Ciphertext, &env.DataIV); err != nil {
		t.Fatal(err)
	}
	pt, err := pkgcrypto.DecryptEnvelope(key, &env)
	return string(pt), err
}

func readText(t *testing.T, db *sql.DB, key []byte, tenant, id string) (string, error) {
	t.Helper()
	var iv, dek, ct, div string
	if err := db.QueryRow(`SELECT iv, dek, ciphertext, data_iv FROM mektest_text WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&iv, &dek, &ct, &div); err != nil {
		t.Fatal(err)
	}
	env := &pkgcrypto.EnvelopeCiphertext{}
	env.WrappedDEKIV, _ = unb64(iv)
	env.WrappedDEK, _ = unb64(dek)
	env.Ciphertext, _ = unb64(ct)
	env.DataIV, _ = unb64(div)
	pt, err := pkgcrypto.DecryptEnvelope(key, env)
	return string(pt), err
}

func events(rec *routetest.Recorder, action string) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	for _, e := range rec.Events() {
		if e.Action == action {
			out[e.Event.TenantID] = e.Event.Details
		}
	}
	return out
}

// exercise runs the lifecycle against one database: data under a public
// dev key and an old environment key, the upgrade, a restart, a restored
// row, a keycore rotation, a wrong key, and a cluster member.
func exercise(t *testing.T, db *sql.DB) {
	ctx := context.Background()
	setupDB(t, db)
	dev, env := rnd(t), rnd(t)
	legacy := []LegacyKey{{Name: "dev_mek", Key: dev, Public: true}, {Name: "env_mek", Key: env}}
	kc := newFakeKeycore(t)

	put(t, db, dev, "t-a", "s1", 1, "a-v1")
	put(t, db, dev, "t-a", "s1", 2, "a-v2")
	put(t, db, env, "t-b", "s2", 1, "b-v1")
	put(t, db, rnd(t), "t-b", "lost", 1, "?")
	putText(t, db, dev, "t-a", "x1", "legacy", "text-1")
	putText(t, db, rnd(t), "t-a", "x2", "crwk", "untouched") // outside Where: never scanned

	rec := &routetest.Recorder{}
	opts := Options{Tables: testTables, Source: kc, DB: db, Audit: rec, Logf: t.Logf, Legacy: legacy}
	k, err := Open(ctx, opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	cur := kc.versions[1]
	if !pkgcrypto.ConstantTimeEqual(k.Current(), cur) || k.Version() != 1 {
		t.Fatal("keyring does not hold keycore's v1 key")
	}
	for _, c := range []struct {
		tenant, item string
		v            int
		want         string
	}{{"t-a", "s1", 1, "a-v1"}, {"t-a", "s1", 2, "a-v2"}, {"t-b", "s2", 1, "b-v1"}} {
		if got, err := read(t, db, cur, c.tenant, c.item, c.v); err != nil || got != c.want {
			t.Fatalf("%s/%s v%d = %q %v", c.tenant, c.item, c.v, got, err)
		}
	}
	if got, err := readText(t, db, cur, "t-a", "x1"); err != nil || got != "text-1" {
		t.Fatalf("base64 row: %q %v", got, err)
	}
	if _, err := read(t, db, dev, "t-a", "s1", 1); err == nil {
		t.Fatal("the public dev key still opens a stored row")
	}
	if d := events(rec, "dev_mek_rewrapped")["t-a"]; d == nil || d["item_count"] != 1 {
		t.Fatalf("dev_mek_rewrapped: %+v", rec.Events())
	}
	if d := events(rec, "mek_rewrapped")["t-b"]; d == nil || d["from"] != "env_mek" {
		t.Fatalf("mek_rewrapped from env: %+v", rec.Events())
	}
	if d := events(rec, "mek_unreadable")["t-b"]; d == nil || d["item_count"] != 1 {
		t.Fatalf("mek_unreadable: %+v", rec.Events())
	}
	exp, _ := k.Exposures(ctx, "t-a", true)
	if len(exp) != 2 { // s1 (thing) and x1 (text_thing); env-key rows aren't public
		t.Fatalf("exposure register t-a: %+v", exp)
	}
	if exp, _ := k.Exposures(ctx, "t-b", true); len(exp) != 0 {
		t.Fatalf("non-public key recorded as exposed: %+v", exp)
	}

	// Restart: nothing to do, nothing emitted.
	rec.Reset()
	if _, err := Open(ctx, opts); err != nil || len(rec.Events()) != 0 {
		t.Fatalf("restart: %v %+v", err, rec.Events())
	}

	// A restore brings back an old row; the periodic rescan moves it.
	put(t, db, dev, "t-c", "s3", 1, "restored")
	if _, err := k.scan(ctx, k.legacy); err != nil {
		t.Fatal(err)
	}
	if got, err := read(t, db, cur, "t-c", "s3", 1); err != nil || got != "restored" {
		t.Fatalf("restored row: %q %v", got, err)
	}
	if exp, _ := k.Exposures(ctx, "t-c", true); len(exp) != 1 {
		t.Fatalf("restored row not registered: %+v", exp)
	}

	// Remediation closes the entry once, and is audited.
	rec.Reset()
	if ok, err := k.Remediate(ctx, "t-a", "thing", "s1", "rotated", "u1"); !ok || err != nil {
		t.Fatalf("remediate: %v %v", ok, err)
	}
	if ok, _ := k.Remediate(ctx, "t-a", "thing", "s1", "rotated", "u1"); ok {
		t.Fatal("remediated twice")
	}
	if len(events(rec, "mek_exposure_remediated")) != 1 {
		t.Fatalf("remediation not audited: %+v", rec.Events())
	}

	// Keycore rotation: the next start moves everything to v2.
	kc.rotate(t)
	rec.Reset()
	k2, err := Open(ctx, opts)
	if err != nil || k2.Version() != 2 {
		t.Fatalf("rotation open: v%d %v", k2.Version(), err)
	}
	if got, err := read(t, db, kc.versions[2], "t-a", "s1", 2); err != nil || got != "a-v2" {
		t.Fatalf("after rotation: %q %v", got, err)
	}
	if d := events(rec, "mek_rewrapped")["t-a"]; d == nil || d["from"] != "previous_version" {
		t.Fatalf("rotation events: %+v", rec.Events())
	}

	// A key that doesn't match the record is refused, on a primary and a member.
	for _, member := range []bool{false, true} {
		bad := *kc
		bad.versions = map[int][]byte{1: rnd(t), 2: rnd(t)}
		o := opts
		o.Source, o.Member = &bad, func(context.Context) bool { return member }
		rec.Reset()
		if _, err := Open(ctx, o); !errors.Is(err, ErrMismatch) {
			t.Fatalf("member=%v: mismatch not refused: %v", member, err)
		}
		if len(events(rec, "mek_check_refused")) != 1 {
			t.Fatalf("member=%v: refusal not audited", member)
		}
	}
	// A member with the right key opens without writing anything.
	put(t, db, dev, "t-d", "s4", 1, "member-sees")
	o := opts
	o.Member = func(context.Context) bool { return true }
	rec.Reset()
	if _, err := Open(ctx, o); err != nil || len(rec.Events()) != 0 {
		t.Fatalf("member open: %v %+v", err, rec.Events())
	}
	if _, err := read(t, db, dev, "t-d", "s4", 1); err != nil {
		t.Fatal("a member re-wrapped a replicated row")
	}
}

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{UseSQLite: true, SQLitePath: ":memory:", MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.SQL()
}

func TestMEKLifecycleSQLite(t *testing.T) { exercise(t, openSQLite(t)) }

func TestMEKLifecyclePostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	exercise(t, conn.SQL())
}

// A row that can't be rewritten blocks the start; nothing is recorded.
func TestRewrapFailureRefusesStart(t *testing.T) {
	db := openSQLite(t)
	setupDB(t, db)
	dev := rnd(t)
	put(t, db, dev, "t1", "s1", 1, "v")
	if _, err := db.Exec(`CREATE TRIGGER mektest_ro BEFORE UPDATE ON mektest_values BEGIN SELECT RAISE(ABORT, 'read-only'); END`); err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	_, err := Open(context.Background(), Options{Tables: testTables, Source: newFakeKeycore(t), DB: db, Audit: rec, Legacy: []LegacyKey{{Name: "dev_mek", Key: dev, Public: true}}})
	if err == nil {
		t.Fatal("start allowed with a row still under the public key")
	}
	if d := events(rec, "dev_mek_rewrap_refused")["t1"]; d == nil || d["reason"] != "rewrap_failed" {
		t.Fatalf("refusal not audited: %+v", rec.Events())
	}
	if _, ok, _ := readState(context.Background(), db, testTables.StateTable); ok {
		t.Fatal("state recorded after a failed migration")
	}
}

func TestKeycoreUnavailableRefusesStart(t *testing.T) {
	db := openSQLite(t)
	setupDB(t, db)
	kc := newFakeKeycore(t)
	kc.fail = errors.New("connection refused")
	if _, err := Open(context.Background(), Options{Tables: testTables, Source: kc, DB: db, Legacy: []LegacyKey{}}); err == nil {
		t.Fatal("opened without keycore")
	}
}

func TestExposureAndRewrapRoutes(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	setupDB(t, db)
	dev := rnd(t)
	put(t, db, dev, "t1", "s1", 1, "v")
	k, err := Open(ctx, Options{Tables: testTables, Source: newFakeKeycore(t), DB: db, Legacy: []LegacyKey{{Name: "dev_mek", Key: dev, Public: true}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := &routetest.Recorder{}
	r := route.New("demo", rec, nil)
	k.Routes(r, "demo")
	routetest.RefusalsAudited(t, r, rec)
	do := func(method, path, body string, c *pkgauth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), c))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	admin := &pkgauth.Claims{UserID: "admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	if w := do("GET", "/mek/exposure", "", admin); w.Code != 200 || !strings.Contains(w.Body.String(), `"item_id":"s1"`) || !strings.Contains(w.Body.String(), `"open":1`) {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/mek/exposure/thing/s1/acknowledge", `{"reason":"short"}`, admin); w.Code != 400 {
		t.Fatalf("acknowledge without a real reason: %d", w.Code)
	}
	if w := do("POST", "/mek/exposure/thing/s1/acknowledge", `{"reason":"test data, never used in production"}`, admin); w.Code != 200 {
		t.Fatalf("acknowledge: %d %s", w.Code, w.Body)
	}
	if exp, _ := k.Exposures(ctx, "t1", true); len(exp) != 0 {
		t.Fatalf("still open: %+v", exp)
	}

	// Re-wrap of backup contents: governance only.
	env, _ := pkgcrypto.EncryptEnvelope(dev, []byte("in-backup"))
	body := `{"entries":[{"iv":"` + b64(env.WrappedDEKIV) + `","dek":"` + b64(env.WrappedDEK) + `"},{"iv":"AAAA","dek":"AAAA"}]}`
	if w := do("POST", "/mek/rewrap-legacy", body, admin); w.Code != http.StatusForbidden {
		t.Fatalf("admin re-wrapped backup contents: %d", w.Code)
	}
	gov := &pkgauth.Claims{ClientID: GovernanceClient, TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	w := do("POST", "/mek/rewrap-legacy", body, gov)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"rewrapped"`) || !strings.Contains(w.Body.String(), `"status":"unknown"`) {
		t.Fatalf("governance re-wrap: %d %s", w.Code, w.Body)
	}
	if e := rec.Last(t); e.Action != "mek_backup_rewrap" || e.Event.Details["rewrapped"] != 1 {
		t.Fatalf("re-wrap not audited: %+v", e)
	}
}

// Every catalogued service is valid and its migrations create its tables.
func TestCatalogIsValidAndMigrated(t *testing.T) {
	dirs := map[string]string{"secrets": "secrets", "cloud": "cloud", "ekm": "ekm", "certs": "certs"}
	for name, st := range Catalog {
		if err := st.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		files, _ := os.ReadDir("../../services/" + dirs[name] + "/migrations")
		var all strings.Builder
		for _, f := range files {
			b, _ := os.ReadFile("../../services/" + dirs[name] + "/migrations/" + f.Name())
			all.Write(b)
		}
		for _, table := range []string{st.StateTable, st.ExposureTable} {
			if !strings.Contains(all.String(), "CREATE TABLE IF NOT EXISTS "+table+" (") {
				t.Errorf("%s: no migration creates %s (use mek.SchemaSQL)", name, table)
			}
		}
	}
}

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

func randomMEK(t testing.TB) []byte {
	t.Helper()
	k, err := pkgcrypto.RandomBytes(mekLen)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

// A real start: main() runs in a child process with no MEK configured and
// must exit before booting anything, naming the variable.
func TestStartWithoutMEKIsRefused(t *testing.T) {
	if os.Getenv("SECRETS_TEST_RUN_MAIN") == "1" {
		main()
		return
	}
	cases := map[string]string{
		"unset":           "",
		"public dev key":  b64(legacyDevMEK()),
		"not 32 bytes":    b64([]byte("too-short-key")),
		"patterned value": b64([]byte("0123456789ABCDEF0123456789ABCDEF")),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartWithoutMEKIsRefused$")
			cmd.Env = append(os.Environ(), "SECRETS_TEST_RUN_MAIN=1", envMEK+"="+value)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() == 0 {
				t.Fatalf("service started without a valid MEK (err=%v):\n%s", err, out)
			}
			if !strings.Contains(string(out), "refusing to start") || !strings.Contains(string(out), envMEK) {
				t.Fatalf("refusal does not name %s:\n%s", envMEK, out)
			}
		})
	}
}

func TestLoadMEKsValidates(t *testing.T) {
	good, other := randomMEK(t), randomMEK(t)
	env := func(cur, prev string) func(string) string {
		return func(k string) string {
			return map[string]string{envMEK: cur, envPreviousMEK: prev}[k]
		}
	}
	bad := map[string]func(string) string{
		"missing":             env("", ""),
		"not base64":          env("!!not-base64!!", ""),
		"33 bytes":            env(b64(append(randomMEK(t), 1)), ""),
		"public dev key":      env(b64(legacyDevMEK()), ""),
		"one repeated byte":   env(b64(make([]byte, mekLen)), ""),
		"previous = current":  env(b64(good), b64(good)),
		"previous is invalid": env(b64(good), "short"),
	}
	for name, getenv := range bad {
		if _, err := loadMEKs(getenv); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	keys, err := loadMEKs(env(b64(good), b64(other)))
	if err != nil || !pkgcrypto.ConstantTimeEqual(keys.Current, good) || !pkgcrypto.ConstantTimeEqual(keys.Previous, other) {
		t.Fatalf("valid keys rejected: %v", err)
	}
}

func createMEKStateTableForTest(t *testing.T, conn *pkgdb.DB) {
	t.Helper()
	ddl, err := os.ReadFile("migrations/003_mek_state.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().Exec(string(ddl)); err != nil {
		t.Fatalf("create secrets_mek_state: %v", err)
	}
}

// eventsByAction indexes recorded events as action -> tenant -> details.
func eventsByAction(rec *routetest.Recorder) map[string]map[string]map[string]interface{} {
	out := map[string]map[string]map[string]interface{}{}
	for _, e := range rec.Events() {
		if out[e.Action] == nil {
			out[e.Action] = map[string]map[string]interface{}{}
		}
		out[e.Action][e.Event.TenantID] = e.Event.Details
	}
	return out
}

func mustCreate(t *testing.T, svc *Service, tenant, name, value string) Secret {
	t.Helper()
	s, err := svc.CreateSecret(context.Background(), CreateSecretRequest{TenantID: tenant, Name: name, SecretType: "password", Value: value, CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustRead(t *testing.T, svc *Service, tenant, id, want string) {
	t.Helper()
	out, err := svc.GetSecretValue(context.Background(), tenant, id, "raw")
	if err != nil || out.Value != want {
		t.Fatalf("read %s/%s = %q, %v; want %q", tenant, id, out.Value, err, want)
	}
}

// allWrappedUnder reports whether every stored DEK opens under mek.
func allWrappedUnder(t *testing.T, store *SQLStore, mek []byte) bool {
	t.Helper()
	rows, err := store.PageWrappedDEKs(context.Background(), wrappedDEK{}, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if !pkgcrypto.EnvelopeWrappedUnder(mek, &pkgcrypto.EnvelopeCiphertext{WrappedDEKIV: r.IV, WrappedDEK: r.DEK}) {
			return false
		}
	}
	return len(rows) > 0
}

// exerciseMEKMigration runs the whole lifecycle against one database:
// data written under the public dev key, the upgrade that re-wraps it, a
// restart, a rotation, a wrong key, and a cluster member.
func exerciseMEKMigration(t *testing.T, conn *pkgdb.DB) {
	ctx := context.Background()
	store := NewSQLStore(conn)
	dev := legacyDevMEK()

	// What earlier releases did: every value wrapped under the dev key.
	old := NewService(store, dev)
	a := mustCreate(t, old, "tenant-a", "db", "a-v1")
	if _, err := old.RotateSecret(ctx, "tenant-a", a.ID, "a-v2", "tester"); err != nil {
		t.Fatal(err)
	}
	b := mustCreate(t, old, "tenant-b", "api", "b-v1")

	// Upgrade: a real MEK is configured.
	cur := randomMEK(t)
	rec := &routetest.Recorder{}
	if err := migrateMEK(ctx, store, mekKeys{Current: cur}, rec, false, t.Logf); err != nil {
		t.Fatalf("migration: %v", err)
	}
	svc := NewService(store, cur)
	mustRead(t, svc, "tenant-a", a.ID, "a-v2")
	mustRead(t, svc, "tenant-b", b.ID, "b-v1")
	if !allWrappedUnder(t, store, cur) {
		t.Fatal("a stored DEK is not under the configured MEK")
	}
	if _, err := old.GetSecretValue(ctx, "tenant-a", a.ID, "raw"); err == nil {
		t.Fatal("the public dev key still decrypts a stored value")
	}
	ev := eventsByAction(rec)["dev_mek_rewrapped"]
	if ev["tenant-a"]["count"] != 2 || ev["tenant-b"]["count"] != 1 {
		t.Fatalf("dev_mek_rewrapped counts per tenant: %+v", ev)
	}
	if ids, _ := ev["tenant-a"]["secret_ids"].([]string); len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("dev_mek_rewrapped secret_ids: %+v", ev["tenant-a"])
	}
	st, ok, err := store.MEKState(ctx)
	if err != nil || !ok || st.Fingerprint != mekFingerprint(cur) || st.DevRewrapped != 3 {
		t.Fatalf("MEK state %+v %v %v", st, ok, err)
	}

	// Restart with the same key: nothing to do, nothing emitted.
	rec.Reset()
	if err := migrateMEK(ctx, store, mekKeys{Current: cur}, rec, false, t.Logf); err != nil || len(rec.Events()) != 0 {
		t.Fatalf("restart re-migrated: %v %+v", err, rec.Events())
	}

	// Rotation: the old key becomes SECRETS_MEK_PREVIOUS_B64.
	next := randomMEK(t)
	if err := migrateMEK(ctx, store, mekKeys{Current: next, Previous: cur}, rec, false, t.Logf); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	mustRead(t, NewService(store, next), "tenant-a", a.ID, "a-v2")
	if !allWrappedUnder(t, store, next) || eventsByAction(rec)["mek_rewrapped"]["tenant-a"]["count"] != 2 {
		t.Fatalf("rotation incomplete: %+v", rec.Events())
	}

	// A different key without a rotation is refused, on a primary and a member.
	for _, member := range []bool{false, true} {
		rec.Reset()
		err := migrateMEK(ctx, store, mekKeys{Current: randomMEK(t)}, rec, member, t.Logf)
		if !errors.Is(err, errMEKMismatch) {
			t.Fatalf("member=%v: wrong MEK not refused: %v", member, err)
		}
		if d := eventsByAction(rec)["mek_check_refused"][""]; d["reason"] != "mek_mismatch" {
			t.Fatalf("member=%v: refusal not audited: %+v", member, rec.Events())
		}
	}
	// A member with the right key starts and writes nothing.
	rec.Reset()
	if err := migrateMEK(ctx, store, mekKeys{Current: next}, rec, true, t.Logf); err != nil || len(rec.Events()) != 0 {
		t.Fatalf("member start: %v %+v", err, rec.Events())
	}
}

func newMEKTestStore(t *testing.T) (*SQLStore, *pkgdb.DB) {
	t.Helper()
	_, store := newSecretsService(t)
	createMEKStateTableForTest(t, store.db)
	return store, store.db
}

func TestMEKMigrationLifecycle(t *testing.T) {
	_, conn := newMEKTestStore(t)
	exerciseMEKMigration(t, conn)
}

// A cluster member never re-wraps: that would write a replicated table.
func TestMEKMigrationMemberWritesNothing(t *testing.T) {
	store, _ := newMEKTestStore(t)
	s := mustCreate(t, NewService(store, legacyDevMEK()), "t1", "x", "v")
	rec := &routetest.Recorder{}
	if err := migrateMEK(context.Background(), store, mekKeys{Current: randomMEK(t)}, rec, true, t.Logf); err != nil {
		t.Fatal(err)
	}
	if !allWrappedUnder(t, store, legacyDevMEK()) || len(rec.Events()) != 0 {
		t.Fatal("member re-wrapped or emitted")
	}
	if _, ok, _ := store.MEKState(context.Background()); ok {
		t.Fatal("member recorded MEK state")
	}
	mustRead(t, NewService(store, legacyDevMEK()), "t1", s.ID, "v")
}

type failingReplaceStore struct{ *SQLStore }

func (f failingReplaceStore) ReplaceWrappedDEK(context.Context, wrappedDEK, []byte, []byte) (bool, error) {
	return false, errors.New("disk full")
}

// A value left under the public key blocks the start, is audited as refused,
// and is retried on the next start.
func TestMEKRewrapFailureRefusesStart(t *testing.T) {
	store, _ := newMEKTestStore(t)
	s := mustCreate(t, NewService(store, legacyDevMEK()), "t1", "x", "v")
	cur := randomMEK(t)
	rec := &routetest.Recorder{}
	err := migrateMEK(context.Background(), failingReplaceStore{store}, mekKeys{Current: cur}, rec, false, t.Logf)
	if err == nil {
		t.Fatal("start allowed with values still under the public key")
	}
	e := rec.Last(t)
	if e.Action != "dev_mek_rewrap_refused" || e.Event.Result != "refused" || e.Event.Details["reason"] != "rewrap_failed" || e.Event.TenantID != "t1" {
		t.Fatalf("refusal event %+v", e)
	}
	if _, ok, _ := store.MEKState(context.Background()); ok {
		t.Fatal("MEK state recorded after a failed migration")
	}
	if err := migrateMEK(context.Background(), store, mekKeys{Current: cur}, rec, false, t.Logf); err != nil {
		t.Fatalf("retry: %v", err)
	}
	mustRead(t, NewService(store, cur), "t1", s.ID, "v")
}

// Rows no configured key opens are reported, not silently skipped, and don't
// block the start (they were unreadable before the migration too).
func TestMEKUnreadableRowsAreAudited(t *testing.T) {
	store, _ := newMEKTestStore(t)
	mustCreate(t, NewService(store, randomMEK(t)), "t1", "lost", "v")
	rec := &routetest.Recorder{}
	if err := migrateMEK(context.Background(), store, mekKeys{Current: randomMEK(t)}, rec, false, t.Logf); err != nil {
		t.Fatal(err)
	}
	e := rec.Last(t)
	if e.Action != "mek_unreadable" || e.Event.Result != "failure" || e.Event.Details["secret_count"] != 1 {
		t.Fatalf("unreadable rows not audited: %+v", e)
	}
	if st, _, _ := store.MEKState(context.Background()); st.Unreadable != 1 {
		t.Fatalf("state %+v", st)
	}
}

func TestMEKMigrationPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database to run the MEK migration against Postgres")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE secrets, secret_values, secret_audit_log, secrets_mek_state`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	exerciseMEKMigration(t, conn)
}

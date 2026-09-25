package clusterrepl

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Integration test against two real Postgres servers (wal_level=logical).
// Runs only when these are set, e.g. by scripts/test-cluster-replication.sh:
//
//	VECTA_REPL_PRIMARY_DSN   primary, as reached from the test (superuser)
//	VECTA_REPL_MEMBER_DSN    member, as reached from the test (superuser)
//	VECTA_REPL_PRIMARY_HOST  primary host:port, as reached from the member's server
func openEnv(t *testing.T, key string) *sql.DB {
	t.Helper()
	dsn := os.Getenv(key)
	if dsn == "" {
		t.Skip("set VECTA_REPL_PRIMARY_DSN, VECTA_REPL_MEMBER_DSN and VECTA_REPL_PRIMARY_HOST to run")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func applyMigrations(t *testing.T, db *sql.DB, service string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join("..", "..", "services", service, "migrations", "*.sql"))
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(raw)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// seedNode creates what a freshly installed KMS node has: the root tenant, a
// node-local bootstrap admin and a node-local internal service identity.
func seedNode(t *testing.T, db *sql.DB, suffix string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO auth_tenants (id, name) VALUES ('root','Root') ON CONFLICT DO NOTHING`)
	mustExec(t, db, `INSERT INTO auth_users (id, tenant_id, username, email, pwd_hash, role, node_local) VALUES ('admin-`+suffix+`','root','admin','admin@`+suffix+`','\x00','admin',TRUE)`)
	mustExec(t, db, `INSERT INTO auth_client_registrations (id, tenant_id, client_name, client_type, contact_email, requested_role, node_local) VALUES ('kms-keycore','root','kms-keycore','service','svc@`+suffix+`','service',TRUE)`)
	mustExec(t, db, `INSERT INTO auth_api_keys (id, tenant_id, client_id, key_hash, name, permissions, node_local) VALUES ('akey-`+suffix+`','root','kms-keycore','\x01','kms-keycore service identity','["service.internal"]',TRUE)`)
}

func TestSelectiveReplicationBetweenTwoNodes(t *testing.T) {
	primary := openEnv(t, "VECTA_REPL_PRIMARY_DSN")
	member := openEnv(t, "VECTA_REPL_MEMBER_DSN")
	primaryHost := os.Getenv("VECTA_REPL_PRIMARY_HOST")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for _, db := range []*sql.DB{primary, member} {
		for _, svc := range []string{"auth", "policy", "secrets"} {
			applyMigrations(t, db, svc)
		}
	}
	pe, me := New(primary), New(member)
	if lvl, _ := pe.WALLevel(ctx); lvl != "logical" {
		t.Fatalf("primary wal_level=%s, need logical", lvl)
	}

	seedNode(t, primary, "primary")
	seedNode(t, member, "member")
	P := "(id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES "
	mustExec(t, primary, `INSERT INTO auth_users (id, tenant_id, username, email, pwd_hash, role) VALUES ('alice','root','alice','alice@corp','\x00','tenant-admin')`)
	mustExec(t, primary, `INSERT INTO auth_sessions (id, tenant_id, user_id, token_hash, expires_at) VALUES ('s1','root','alice','\x00',now() + interval '1 hour')`)
	mustExec(t, primary, `INSERT INTO policies `+P+`('p1','root','deny-export','rego','y','{}','c1','alice','alice')`)
	mustExec(t, primary, `INSERT INTO secrets (id, tenant_id, name, secret_type, created_by) VALUES ('sec1','root','db-pass','password','alice')`)
	mustExec(t, member, `INSERT INTO policies `+P+`('local','root','member-bootstrap','rego','y','{}','c0','boot','boot')`)

	pubs, err := pe.EnsurePublications(ctx, []string{"auth", "policy", "secrets"})
	if err != nil || len(pubs) != 3 {
		t.Fatalf("publications: %+v %v", pubs, err)
	}
	for _, p := range pubs {
		if !p.Changed {
			t.Fatalf("a new publication must report Changed (it is audited): %s", p.Publication)
		}
		for _, tbl := range p.Tables {
			if tbl == "auth_sessions" || tbl == "policy_evaluations" {
				t.Fatalf("node-local table %s must never be published", tbl)
			}
		}
	}
	if again, _ := pe.EnsurePublications(ctx, []string{"auth", "policy", "secrets"}); len(again) != 3 || again[0].Changed || again[1].Changed || again[2].Changed {
		t.Fatalf("unchanged publications must not report Changed (no audit noise): %+v", again)
	}

	// The member reads with its own restricted role, granted only its components.
	const pw = "repl-test-password-0123456789abcdef"
	role, err := pe.EnsureReplicationRole(ctx, "node-2", pw, []string{"auth", "policy"})
	if err != nil {
		t.Fatal(err)
	}
	conn := "host=" + strings.Split(primaryHost, ":")[0] + " port=" + strings.Split(primaryHost, ":")[1] + " user=" + role + " password=" + pw + " dbname=postgres sslmode=disable"
	for _, c := range []string{"auth", "policy"} {
		if err := me.Subscribe(ctx, "node-2", c, conn, SubscribeOptions{ResetLocalData: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := me.WaitReady(ctx, "node-2"); err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		db   *sql.DB
		q    string
		want int
		why  string
	}{
		{member, `SELECT count(*) FROM auth_users WHERE id='alice'`, 1, "shared users replicate"},
		{member, `SELECT count(*) FROM policies WHERE id='p1'`, 1, "assigned components replicate"},
		{member, `SELECT count(*) FROM policies WHERE id='local'`, 0, "member bootstrap rows are reset"},
		{member, `SELECT count(*) FROM auth_users WHERE id='admin-member'`, 1, "the member keeps its own local admin"},
		{member, `SELECT count(*) FROM auth_users WHERE id='admin-primary'`, 0, "the primary's local admin never leaves the primary"},
		{member, `SELECT count(*) FROM auth_api_keys WHERE id='akey-member'`, 1, "the member keeps its own service identity"},
		{member, `SELECT count(*) FROM auth_api_keys WHERE id='akey-primary'`, 0, "the primary's service identity never leaves the primary"},
		{member, `SELECT count(*) FROM auth_sessions`, 0, "node-local tables do not replicate"},
		{member, `SELECT count(*) FROM secrets`, 0, "unassigned components do not replicate"},
		{member, `SELECT count(*) FROM auth_tenants WHERE id='root'`, 1, "the root tenant is the primary's copy"},
	}
	for _, c := range checks {
		if got := count(t, c.db, c.q); got != c.want {
			t.Fatalf("%s: %s = %d, want %d", c.why, c.q, got, c.want)
		}
	}

	// Ongoing changes: shared rows stream; node-local rows stay put.
	mustExec(t, primary, `UPDATE auth_users SET email='alice@new' WHERE id='alice'`)
	mustExec(t, primary, `UPDATE auth_users SET email='changed@primary' WHERE id='admin-primary'`)
	mustExec(t, primary, `INSERT INTO policies `+P+`('p2','root','second','rego','y','{}','c2','alice','alice')`)
	waitFor(t, func() bool {
		return count(t, member, `SELECT count(*) FROM auth_users WHERE id='alice' AND email='alice@new'`) == 1 &&
			count(t, member, `SELECT count(*) FROM policies WHERE id='p2'`) == 1
	}, "shared changes on the primary reach the member")
	if count(t, member, `SELECT count(*) FROM auth_users WHERE email='changed@primary'`) != 0 {
		t.Fatal("changes to the primary's node-local rows must not replicate")
	}

	sts, err := me.SubscriptionStatuses(ctx, "node-2")
	if err != nil || len(sts) != 2 {
		t.Fatalf("status: %+v %v", sts, err)
	}
	for _, s := range sts {
		if !s.Ready || !s.WorkerRunning || len(s.Tables) == 0 {
			t.Fatalf("subscription %s not reported ready: %+v", s.Subscription, s)
		}
	}

	// Removing the member leaves no slots or role behind on the primary.
	for _, c := range []string{"auth", "policy"} {
		if err := me.Unsubscribe(ctx, "node-2", c); err != nil {
			t.Fatal(err)
		}
	}
	if err := pe.RemoveMember(ctx, "node-2"); err != nil {
		t.Fatal(err)
	}
	if count(t, primary, `SELECT count(*) FROM pg_replication_slots WHERE starts_with(slot_name, 'vecta_sub_node_2_')`) != 0 ||
		count(t, primary, `SELECT count(*) FROM pg_roles WHERE rolname = $1`, role) != 0 {
		t.Fatal("RemoveMember must drop the member's slots and role")
	}
	for _, p := range pubs {
		_, _ = primary.Exec(`DROP PUBLICATION IF EXISTS "` + p.Publication + `"`)
	}
}

package clusterrepl

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Integration test against two real Postgres servers (wal_level=logical).
// Runs only when these are set, e.g. by scripts/test-cluster-replication.sh:
//
//	VECTA_REPL_PRIMARY_DSN   primary, as reached from the test
//	VECTA_REPL_MEMBER_DSN    member, as reached from the test
//	VECTA_REPL_PRIMARY_CONN  primary, as reached from the member's server
func openEnv(t *testing.T, key string) *sql.DB {
	t.Helper()
	dsn := os.Getenv(key)
	if dsn == "" {
		t.Skip("set VECTA_REPL_PRIMARY_DSN, VECTA_REPL_MEMBER_DSN and VECTA_REPL_PRIMARY_CONN to run")
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

func TestSelectiveReplicationBetweenTwoNodes(t *testing.T) {
	primary := openEnv(t, "VECTA_REPL_PRIMARY_DSN")
	member := openEnv(t, "VECTA_REPL_MEMBER_DSN")
	conn := os.Getenv("VECTA_REPL_PRIMARY_CONN")
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

	// Primary data: a tenant (auth), a session (node-local), a policy, a secret.
	mustExec(t, primary, `INSERT INTO auth_tenants (id, name, status) VALUES ('t1','Tenant One','active')`)
	mustExec(t, primary, `INSERT INTO auth_users (id, tenant_id, username, email, pwd_hash, role) VALUES ('u1','t1','alice','alice@t1','\x00','admin')`)
	mustExec(t, primary, `INSERT INTO auth_sessions (id, tenant_id, user_id, token_hash, expires_at) VALUES ('s1','t1','u1','\x00',now() + interval '1 hour')`)
	mustExec(t, primary, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('p1','t1','deny-export','rego','y','{}','c1','admin','admin')`)
	mustExec(t, primary, `INSERT INTO secrets (id, tenant_id, name, secret_type, created_by) VALUES ('sec1','t1','db-pass','password','admin')`)
	// Member bootstrap row that collides with nothing but must be reset.
	mustExec(t, member, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('local','t1','member-bootstrap','rego','y','{}','c0','boot','boot')`)

	pubs, err := pe.EnsurePublications(ctx, []string{"auth", "policy", "secrets"})
	if err != nil || len(pubs) != 3 {
		t.Fatalf("publications: %+v %v", pubs, err)
	}
	for _, p := range pubs {
		if !p.Changed {
			t.Fatalf("a new publication must report Changed (it is audited): %s", p.Publication)
		}
	}
	again, err := pe.EnsurePublications(ctx, []string{"auth", "policy", "secrets"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range again {
		if p.Changed {
			t.Fatalf("an unchanged publication must not report Changed (no audit noise): %s", p.Publication)
		}
	}
	for _, p := range pubs {
		for _, tbl := range p.Tables {
			if tbl == "auth_sessions" || tbl == "policy_evaluations" {
				t.Fatalf("node-local table %s must never be published", tbl)
			}
		}
	}

	// The member is assigned auth and policy, but not secrets.
	for _, c := range []string{"auth", "policy"} {
		if err := me.Subscribe(ctx, "node-2", c, conn, SubscribeOptions{ResetLocalData: true}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, c := range []string{"auth", "policy"} {
			_ = me.Unsubscribe(context.Background(), "node-2", c)
		}
		for _, p := range pubs {
			_, _ = primary.Exec(`DROP PUBLICATION IF EXISTS "` + p.Publication + `"`)
		}
	})
	if err := me.WaitReady(ctx, "node-2"); err != nil {
		t.Fatal(err)
	}

	if count(t, member, `SELECT count(*) FROM auth_tenants WHERE id='t1'`) != 1 ||
		count(t, member, `SELECT count(*) FROM policies WHERE id='p1'`) != 1 {
		t.Fatal("assigned components must be copied to the member")
	}
	if count(t, member, `SELECT count(*) FROM policies WHERE id='local'`) != 0 {
		t.Fatal("the member's bootstrap rows must be reset before the copy")
	}
	if count(t, member, `SELECT count(*) FROM auth_sessions`) != 0 {
		t.Fatal("node-local tables must not replicate")
	}
	if count(t, member, `SELECT count(*) FROM secrets`) != 0 {
		t.Fatal("unassigned components must not replicate")
	}

	// Ongoing changes stream to the member.
	mustExec(t, primary, `UPDATE policies SET name='deny-export-v2' WHERE id='p1'`)
	mustExec(t, primary, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('p2','t1','second','rego','y','{}','c2','admin','admin')`)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if count(t, member, `SELECT count(*) FROM policies WHERE (id='p1' AND name='deny-export-v2') OR id='p2'`) == 2 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if count(t, member, `SELECT count(*) FROM policies WHERE (id='p1' AND name='deny-export-v2') OR id='p2'`) != 2 {
		t.Fatal("updates and inserts on the primary must reach the member")
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
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

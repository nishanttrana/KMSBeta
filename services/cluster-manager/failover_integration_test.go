package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vecta-kms/pkg/clusterrepl"
	"vecta-kms/pkg/clusterstate"
)

// Failover on three real Postgres servers (scripts/test-cluster-replication.sh):
// two members join, the primary is lost, the member that has applied the most
// is elected, the other re-subscribes to it and receives its writes and no
// more of the old primary's, and the old primary fences itself when it
// returns. Time for the election is a test clock; replication is real.

type itNode struct {
	id    string
	svc   *Service
	db    *sql.DB
	eng   *clusterrepl.Engine
	audit *captureAudit
	srv   *httptest.Server
	down  atomic.Bool
}

func TestFailoverEndToEnd(t *testing.T) {
	if os.Getenv("VECTA_REPL_MEMBER2_DSN") == "" {
		t.Skip("set VECTA_REPL_MEMBER2_DSN and VECTA_REPL_*_HOST (scripts/test-cluster-replication.sh) to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	clk := &testClock{t: time.Now().UTC()}
	nodes := map[string]*itNode{}
	for _, c := range []struct{ id, dsn, host string }{
		{"node-1", "VECTA_REPL_PRIMARY_DSN", "VECTA_REPL_PRIMARY_HOST"},
		{"node-2", "VECTA_REPL_MEMBER_DSN", "VECTA_REPL_MEMBER_HOST"},
		{"node-3", "VECTA_REPL_MEMBER2_DSN", "VECTA_REPL_MEMBER2_HOST"},
	} {
		pdb, sqlDB := openNode(t, c.dsn)
		n := &itNode{id: c.id, db: sqlDB, eng: clusterrepl.New(sqlDB), audit: &captureAudit{}}
		t.Setenv("CLUSTER_NODE_ID", c.id)
		n.svc = NewService(NewSQLStore(pdb), n.audit).WithReplication(n.eng).WithFailover(NewSQLStore(pdb), n.eng)
		n.svc.now = clk.Now
		n.svc.fo.lastContact = clk.Now()
		h := NewHandler(n.svc)
		n.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if n.down.Load() {
				hj, _ := w.(http.Hijacker)
				conn, _, _ := hj.Hijack()
				_ = conn.Close()
				return
			}
			h.ServeHTTP(w, r)
		}))
		t.Cleanup(n.srv.Close)
		sum := sha256.Sum256(n.srv.Certificate().Raw)
		hp := strings.Split(os.Getenv(c.host), ":")
		n.svc.WithJoin(&fakeKeycore{mek: []byte("SHARED-MEK-0123456789abcdef01234")}, joinConfig{advertiseURL: n.srv.URL, tlsFingerprint: hex.EncodeToString(sum[:]),
			pgHost: hp[0], pgPort: hp[1], pgDB: "postgres", pgSSLMode: "disable"})
		nodes[c.id] = n
	}
	a, b, c := nodes["node-1"], nodes["node-2"], nodes["node-3"]
	t.Cleanup(func() {
		bg := context.Background()
		for _, n := range []*itNode{b, c} {
			_, _ = n.eng.Detach(bg, n.id)
		}
		for _, n := range []*itNode{a, b, c} {
			_ = n.eng.DropMemberSlots(bg)
			for _, m := range []string{"node-2", "node-3"} {
				_ = n.eng.RemoveMember(bg, m)
			}
			// The join test runs on the same servers next, and audits the
			// publications it creates.
			if rows, err := n.db.QueryContext(bg, `SELECT pubname FROM pg_publication WHERE starts_with(pubname, 'vecta_pub_')`); err == nil {
				pubs := []string{}
				for rows.Next() {
					var p string
					_ = rows.Scan(&p)
					pubs = append(pubs, p)
				}
				rows.Close() //nolint:errcheck
				for _, p := range pubs {
					_, _ = n.db.ExecContext(bg, `DROP PUBLICATION "`+p+`"`)
				}
			}
			for _, tbl := range []string{"cluster_local_state", "cluster_peers", "cluster_votes", "cluster_member_credentials", "cluster_nodes"} {
				_, _ = n.db.ExecContext(bg, "DELETE FROM "+tbl)
			}
		}
	})

	mustExecJ(t, a.db, `INSERT INTO auth_tenants (id, name) VALUES ('root','Root') ON CONFLICT DO NOTHING`)
	mustExecJ(t, a.db, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('fo-p1','root','one','rego','y','{}','c1','alice','alice') ON CONFLICT DO NOTHING`)
	if err := a.svc.store.UpsertProfile(ctx, ClusterProfile{ID: "prof-policy", TenantID: "root", Name: "policy", Components: []string{"policy"}}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []*itNode{b, c} {
		tok, err := a.svc.CreateJoinToken(ctx, CreateJoinTokenInput{TenantID: "root", TargetNodeID: m.id, TargetNodeName: m.id, ProfileID: "prof-policy", ExpiresMinutes: 10})
		if err != nil {
			t.Fatal(err)
		}
		bundle := EncodeJoinBundle(JoinBundle{PrimaryURL: a.srv.URL, TLSFingerprint: a.svc.joinCfg.tlsFingerprint, TokenID: tok.ID, JoinSecret: tok.IssuedSecret})
		if _, err := m.svc.ConnectToCluster(ctx, ConnectInput{JoinBundle: bundle, Endpoint: m.srv.URL, ConfirmReplace: true}); err != nil {
			t.Fatalf("%s join: %v", m.id, err)
		}
		if err := m.eng.WaitReady(ctx, m.id); err != nil {
			t.Fatal(err)
		}
	}
	// The first join recorded the primary's role; heartbeats spread the cluster.
	if st := clusterstate.NewReader(a.db).Get(ctx); st.Role != clusterstate.RolePrimary || st.ChainNode() != "node-1" {
		t.Fatalf("the primary did not record its role: %+v", st)
	}
	tick := func(ns ...*itNode) {
		for _, n := range ns {
			if !n.down.Load() {
				n.svc.FailoverTick(ctx)
			}
		}
	}
	tick(b, c, a)
	if ok, _ := clusterstate.NewReader(a.db).Get(ctx).WritesAllowed(clk.Now()); !ok {
		t.Fatal("the primary has no lease with both members heartbeating")
	}
	mustExecJ(t, a.db, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('fo-p2','root','two','rego','y','{}','c1','alice','alice')`)
	waitRow(t, ctx, b.db, "fo-p2")
	waitRow(t, ctx, c.db, "fo-p2")

	// The primary's cluster-manager is lost.
	a.down.Store(true)
	for i := 0; i < 3 && clusterstate.NewReader(b.db).Get(ctx).Role != clusterstate.RolePrimary && clusterstate.NewReader(c.db).Get(ctx).Role != clusterstate.RolePrimary; i++ {
		clk.Add(electionTimeout + electionJitter)
		tick(b, c)
	}
	var newP, other *itNode
	switch {
	case clusterstate.NewReader(b.db).Get(ctx).Role == clusterstate.RolePrimary:
		newP, other = b, c
	case clusterstate.NewReader(c.db).Get(ctx).Role == clusterstate.RolePrimary:
		newP, other = c, b
	default:
		t.Fatalf("no member was elected: B %v C %v", b.audit.subjects, c.audit.subjects)
	}
	if newP.audit.count("audit.cluster.promoted") != 1 {
		t.Fatal("promotion not audited")
	}
	// The other member follows, gets replication access on the new primary
	// and copies from it.
	tick(other)
	if st := clusterstate.NewReader(other.db).Get(ctx); st.PrimaryNodeID != newP.id || !st.IsMember() {
		t.Fatalf("%s does not follow %s: %+v", other.id, newP.id, st)
	}
	if err := other.eng.WaitReady(ctx, other.id); err != nil {
		t.Fatal(err)
	}
	mustExecJ(t, newP.db, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('fo-p3','root','three','rego','y','{}','c1','bob','bob')`)
	waitRow(t, ctx, other.db, "fo-p3")
	// Nothing more arrives from the old primary.
	mustExecJ(t, a.db, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('fo-p4','root','four','rego','y','{}','c1','eve','eve')`)
	time.Sleep(3 * time.Second)
	for _, n := range []*itNode{newP, other} {
		var cnt int
		if err := n.db.QueryRow(`SELECT count(*) FROM policies WHERE id='fo-p4'`).Scan(&cnt); err != nil || cnt != 0 {
			t.Fatalf("%s still receives the old primary's writes", n.id)
		}
	}
	// The new primary's forward endpoint accepts the member's credential.
	if _, err := newP.svc.memberFromCredential(ctx, credRequest(other)); err != nil {
		t.Fatalf("the new primary refuses the member's credential: %v", err)
	}
	tick(other, newP)
	if ok, _ := clusterstate.NewReader(newP.db).Get(ctx).WritesAllowed(clk.Now()); !ok {
		t.Fatal("the new primary has no lease")
	}

	// A planned switchover back to the other member: the running primary is
	// fenced first, and the member waits until it has the primary's last
	// write.
	mustExecJ(t, newP.db, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('fo-p5','root','five','rego','y','{}','c1','bob','bob')`)
	res, err := other.svc.PromoteManually(ctx, PromoteInput{Confirm: true, Actor: "test", Reason: "maintenance"})
	if err != nil || !res.CaughtUp {
		t.Fatalf("switchover: %+v %v", res, err)
	}
	waitRow(t, ctx, other.db, "fo-p5")
	if st := clusterstate.NewReader(newP.db).Get(ctx); st.Role != clusterstate.RoleFenced {
		t.Fatalf("the switched-over primary is not fenced: %+v", st)
	}

	// The old primary comes back and fences itself.
	a.down.Store(false)
	tick(a)
	st := clusterstate.NewReader(a.db).Get(ctx)
	if ok, reason := st.WritesAllowed(time.Now()); ok || reason != "node_fenced" || st.Epoch < 2 {
		t.Fatalf("the old primary was not fenced: %+v", st)
	}
}

func credRequest(n *itNode) *http.Request {
	st := clusterstate.NewReader(n.db).Get(context.Background())
	r := httptest.NewRequest(http.MethodPost, "/cluster/peer/heartbeat", nil)
	r.Header.Set("X-Vecta-Cluster-Node", st.NodeID)
	r.Header.Set("X-Vecta-Cluster-Credential", st.ForwardCredential)
	return r
}

func waitRow(t *testing.T, ctx context.Context, db *sql.DB, id string) {
	t.Helper()
	for {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM policies WHERE id=$1`, id).Scan(&n); err == nil && n == 1 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("row %s never replicated", id)
		case <-time.After(300 * time.Millisecond):
		}
	}
}

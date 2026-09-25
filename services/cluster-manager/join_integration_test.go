package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"vecta-kms/pkg/clusterrepl"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
)

// fakeKeycore stands in for keycore's master-key endpoints with the real
// ML-KEM sealing (keycore's own logic is tested in services/keycore).
type fakeKeycore struct {
	mu        sync.Mutex
	mek       []byte
	pending   map[string]*pkgcrypto.KEMRecipient
	installed []byte
}

func (f *fakeKeycore) CreateJoinKey(context.Context) (string, string, error) {
	r, err := pkgcrypto.NewKEMRecipient()
	if err != nil {
		return "", "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pending == nil {
		f.pending = map[string]*pkgcrypto.KEMRecipient{}
	}
	f.pending["jk1"] = r
	return "jk1", base64.StdEncoding.EncodeToString(r.EncapsulationKey()), nil
}

func fp(mek []byte) string {
	s := sha256.Sum256(append([]byte("vecta-mek-fingerprint|"), mek...))
	return hex.EncodeToString(s[:8])
}

func (f *fakeKeycore) ExportMEK(_ context.Context, ek, jctx, _ string) (string, string, error) {
	raw, _ := base64.StdEncoding.DecodeString(ek)
	sealed, err := pkgcrypto.KEMSeal(raw, f.mek, []byte(jctx), "keycore-mek")
	return base64.StdEncoding.EncodeToString(sealed), fp(f.mek), err
}

func (f *fakeKeycore) ImportMEK(_ context.Context, id, sealed, jctx, fingerprint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	mek, err := f.pending[id].Open(raw, []byte(jctx), "keycore-mek")
	if err != nil {
		return err
	}
	if fp(mek) != fingerprint {
		return os.ErrInvalid
	}
	f.installed = mek
	return nil
}

func openNode(t *testing.T, dsnEnv string) (*pkgdb.DB, *sql.DB) {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skip("set VECTA_REPL_PRIMARY_DSN, VECTA_REPL_MEMBER_DSN and VECTA_REPL_PRIMARY_HOST to run")
	}
	db, err := pkgdb.Open(context.Background(), pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, svc := range []string{"cluster-manager", "auth", "keycore", "policy", "governance"} {
		files, _ := filepath.Glob(filepath.Join("..", svc, "migrations", "*.sql"))
		sort.Strings(files)
		for _, f := range files {
			raw, _ := os.ReadFile(f)
			if _, err := db.SQL().Exec(string(raw)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	}
	return db, db.SQL()
}

func TestSecureJoinEndToEnd(t *testing.T) {
	primaryDB, primarySQL := openNode(t, "VECTA_REPL_PRIMARY_DSN")
	memberDB, memberSQL := openNode(t, "VECTA_REPL_MEMBER_DSN")
	host := strings.Split(os.Getenv("VECTA_REPL_PRIMARY_HOST"), ":")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Primary data the member must receive.
	mustExecJ(t, primarySQL, `INSERT INTO auth_tenants (id, name) VALUES ('root','Root') ON CONFLICT DO NOTHING`)
	mustExecJ(t, primarySQL, `INSERT INTO auth_users (id, tenant_id, username, email, pwd_hash, role) VALUES ('alice','root','alice','alice@corp','\x00','tenant-admin') ON CONFLICT DO NOTHING`)
	mustExecJ(t, primarySQL, `INSERT INTO policies (id, tenant_id, name, spec_type, yaml_document, parsed_json, current_commit, created_by, updated_by) VALUES ('p1','root','deny-export','rego','y','{}','c1','alice','alice') ON CONFLICT DO NOTHING`)

	primaryKC := &fakeKeycore{mek: []byte("PRIMARY-MEK-0123456789abcdef0123")}
	memberKC := &fakeKeycore{mek: []byte("MEMBER--MEK-0123456789abcdef0123")}

	t.Setenv("CLUSTER_NODE_ID", "node-1")
	primary := NewService(NewSQLStore(primaryDB), nil).WithReplication(clusterrepl.New(primarySQL))
	t.Setenv("CLUSTER_NODE_ID", "node-2")
	member := NewService(NewSQLStore(memberDB), nil).WithReplication(clusterrepl.New(memberSQL))

	// The primary's cluster-manager behind real TLS; the bundle pins its cert.
	srv := httptest.NewTLSServer(NewHandler(primary))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	primary.WithJoin(primaryKC, joinConfig{advertiseURL: srv.URL, tlsFingerprint: hex.EncodeToString(sum[:]), pgHost: host[0], pgPort: host[1], pgDB: "postgres", pgSSLMode: "disable"})
	member.WithJoin(memberKC, joinConfig{})

	if err := primary.store.UpsertProfile(ctx, ClusterProfile{ID: "prof-policy", TenantID: "root", Name: "policy only", Components: []string{"policy"}}); err != nil {
		t.Fatal(err)
	}
	newBundle := func() string {
		tok, err := primary.CreateJoinToken(ctx, CreateJoinTokenInput{TenantID: "root", TargetNodeID: "node-2", TargetNodeName: "kms-2", ProfileID: "prof-policy", ExpiresMinutes: 10})
		if err != nil {
			t.Fatal(err)
		}
		return EncodeJoinBundle(JoinBundle{PrimaryURL: srv.URL, TLSFingerprint: primary.joinCfg.tlsFingerprint, TokenID: tok.ID, JoinSecret: tok.IssuedSecret})
	}

	// A wrong pin must stop the join before any secret moves.
	bad, _ := DecodeJoinBundle(newBundle())
	bad.TLSFingerprint = strings.Repeat("00", 32)
	if _, err := member.ConnectToCluster(ctx, ConnectInput{JoinBundle: EncodeJoinBundle(bad), ConfirmReplace: true}); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("a mismatched TLS pin must refuse the join, got %v", err)
	}
	if memberKC.installed != nil {
		t.Fatal("no master key may be installed after a refused join")
	}
	if _, err := member.ConnectToCluster(ctx, ConnectInput{JoinBundle: newBundle()}); err == nil {
		t.Fatal("joining without confirm_replace must be refused")
	}

	bundle := newBundle()
	res, err := member.ConnectToCluster(ctx, ConnectInput{JoinBundle: bundle, ConfirmReplace: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, c := range res.Subscribed {
			_ = member.replication.Unsubscribe(context.Background(), "node-2", c)
		}
		_ = primary.replication.RemoveMember(context.Background(), "node-2")
	})
	if !bytes.Equal(memberKC.installed, primaryKC.mek) {
		t.Fatal("the member must receive the primary's master key")
	}
	if strings.Join(res.Components, ",") != "auth,governance,keycore,policy" {
		t.Fatalf("components = %v, want core + policy", res.Components)
	}
	if err := member.replication.WaitReady(ctx, "node-2"); err != nil {
		sts, _ := member.replication.SubscriptionStatuses(context.Background(), "node-2")
		for _, st := range sts {
			var notReady []string
			for _, tbl := range st.Tables {
				if tbl.State != "ready" {
					notReady = append(notReady, tbl.Table+"="+tbl.State)
				}
			}
			t.Logf("%s worker=%v tables=%d not-ready=%v", st.Subscription, st.WorkerRunning, len(st.Tables), notReady)
		}
		t.Fatal(err)
	}
	var n int
	if err := memberSQL.QueryRow(`SELECT count(*) FROM policies WHERE id='p1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the assigned component's data must replicate: %d %v", n, err)
	}
	if err := memberSQL.QueryRow(`SELECT count(*) FROM auth_users WHERE id='alice'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("core auth data must replicate: %d %v", n, err)
	}
	node, err := primary.store.GetNode(ctx, "root", "node-2")
	if err != nil || node.ID != "node-2" {
		t.Fatalf("the primary must register the member: %+v %v", node, err)
	}

	// The token is single-use.
	b, _ := DecodeJoinBundle(bundle)
	if _, err := primary.ExchangeJoin(ctx, ExchangeJoinInput{TokenID: b.TokenID, JoinSecret: b.JoinSecret, NodeID: "node-2", KeycoreJoinKey: "x", ClusterManagerJoinKey: "x"}); err == nil {
		t.Fatal("a consumed join token must not be accepted again")
	}
}

func mustExecJ(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

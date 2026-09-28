package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

func addMerkleSchemaForTest(t *testing.T, s *SQLStore) {
	t.Helper()
	for _, stmt := range []string{
		`CREATE TABLE audit_merkle_epochs (id TEXT NOT NULL, tenant_id TEXT NOT NULL, epoch_number INTEGER NOT NULL, seq_from INTEGER NOT NULL,
			seq_to INTEGER NOT NULL, leaf_count INTEGER NOT NULL, tree_root TEXT NOT NULL, previous_epoch_root TEXT, epoch_hash TEXT,
			chain_node TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id));`,
		`CREATE TABLE audit_merkle_leaves (epoch_id TEXT NOT NULL, tenant_id TEXT NOT NULL, leaf_index INTEGER NOT NULL, event_id TEXT NOT NULL,
			sequence INTEGER NOT NULL, leaf_hash TEXT NOT NULL, chain_node TEXT NOT NULL DEFAULT '', PRIMARY KEY (tenant_id, epoch_id, leaf_index));`,
	} {
		if _, err := s.db.SQL().Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
}

// seedKeyTrail writes, for tenant: other, key, key, other, key (sealed in
// one epoch), then one more key event after the epoch (pending). It returns
// the key's event IDs in write order.
func seedKeyTrail(t *testing.T, s *SQLStore, tenant string) []string {
	t.Helper()
	ctx := context.Background()
	s.SetEventSigningKey([]byte("0123456789abcdef0123456789abcdef"))
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	var ids []string
	write := func(i int, target, action string) {
		ev, _, err := s.PersistEventAndAlert(ctx, AuditEvent{
			TenantID: tenant, Timestamp: base.Add(time.Duration(i) * time.Second), Service: "keycore", Action: action,
			ActorID: "alice", ActorType: "user", TargetType: "key", TargetID: target, Result: "success",
			Details: map[string]interface{}{"i": i},
		}, Alert{}, 60, 5, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if target == "key-1" {
			ids = append(ids, ev.ID)
		}
	}
	write(0, "key-other", "audit.key.create")
	write(1, "key-1", "audit.key.create")
	write(2, "key-1", "audit.key.encrypt")
	write(3, "key-other", "audit.key.encrypt")
	write(4, "key-1", "audit.key.rotate")
	if res, err := s.BuildMerkleEpoch(ctx, tenant, 100); err != nil || res == nil {
		t.Fatalf("seal epoch: %v %v", res, err)
	}
	write(5, "key-1", "audit.key.decrypt")
	return ids
}

func eventResult(t *testing.T, res TargetIntegrity, id string) EventIntegrity {
	t.Helper()
	for _, e := range res.Events {
		if e.EventID == id {
			return e
		}
	}
	t.Fatalf("event %s not in report", id)
	return EventIntegrity{}
}

func checkIntactTrail(t *testing.T, s *SQLStore, tenant string) []string {
	t.Helper()
	ids := seedKeyTrail(t, s, tenant)
	res, err := s.VerifyTarget(context.Background(), tenant, "key-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "intact" || res.EventsChecked != 4 || res.Failed != 0 || res.Sealed != 3 || res.Pending != 1 || res.Unsigned != 0 {
		t.Fatalf("untouched trail: %+v", res)
	}
	for _, e := range res.Events {
		if e.Content != integrityIntact || e.Signature != integrityVerified {
			t.Fatalf("event %s: %+v", e.EventID, e)
		}
		if e.Seal == integritySealed && (e.Proof == nil || !VerifyProof(*e.Proof)) {
			t.Fatalf("sealed event %s has no valid proof: %+v", e.EventID, e.Proof)
		}
	}
	if first := eventResult(t, res, ids[0]); first.Link != integrityLinked {
		t.Fatalf("first key event link = %s", first.Link)
	}
	return ids
}

func TestTargetIntegrityIntactTrail(t *testing.T) {
	s := newAuditStore(t)
	addMerkleSchemaForTest(t, s)
	checkIntactTrail(t, s, "t1")
}

// Each way an attacker with database access could alter a key's history
// must be caught, by a check that does not derive its expectation from the
// altered data (the lineage tamper check compared a hash with itself).
func TestTargetIntegrityRejectsTampering(t *testing.T) {
	cases := []struct {
		name    string
		tamper  func(t *testing.T, s *SQLStore, ids []string) string // returns the event expected to fail
		reasons []string
	}{
		{
			name: "row content edited",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				mustExec(t, s, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[1])
				return ids[1]
			},
			reasons: []string{"content_altered", "merkle_leaf_mismatch"},
		},
		{
			name: "row rewritten with a fresh chain hash",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				ev := loadRow(t, s, ids[1])
				ev.ActorID = "mallory"
				mustExec(t, s, `UPDATE audit_events SET actor_id='mallory', chain_hash=$1 WHERE id=$2`,
					chainHash(ev.PreviousHash, eventHashInput(ev)), ids[1])
				return ids[1]
			},
			reasons: []string{"link_broken", "hmac_mismatch", "merkle_leaf_mismatch"},
		},
		{
			name: "pending row edited",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				mustExec(t, s, `UPDATE audit_events SET result='failure' WHERE id=$1`, ids[3])
				return ids[3]
			},
			reasons: []string{"content_altered"},
		},
		{
			name: "merkle leaf replaced",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				mustExec(t, s, `UPDATE audit_merkle_leaves SET leaf_hash=$1 WHERE event_id=$2`, strings.Repeat("0", 64), ids[0])
				return ids[0]
			},
			reasons: []string{"merkle_leaf_mismatch"},
		},
		{
			name: "sealed root replaced",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				mustExec(t, s, `UPDATE audit_merkle_epochs SET tree_root=$1`, strings.Repeat("f", 64))
				return ids[0]
			},
			reasons: []string{"merkle_root_mismatch"},
		},
		{
			name: "preceding event deleted",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				mustExec(t, s, `DELETE FROM audit_events WHERE target_id='key-other' AND action='audit.key.encrypt'`)
				return ids[2]
			},
			reasons: []string{"link_predecessor_missing"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAuditStore(t)
			addMerkleSchemaForTest(t, s)
			ids := seedKeyTrail(t, s, "t1")
			victim := tc.tamper(t, s, ids)
			res, err := s.VerifyTarget(context.Background(), "t1", "key-1", 0)
			if err != nil {
				t.Fatal(err)
			}
			if res.Verdict != "tampered" || res.Failed == 0 {
				t.Fatalf("tampering not detected: %+v", res)
			}
			got := eventResult(t, res, victim).Failures
			for _, want := range tc.reasons {
				if !containsString(got, want) {
					t.Fatalf("event %s failures %v, want %s", victim, got, want)
				}
			}
		})
	}
}

// A proof served for an event must fail once its leaf is altered: the root
// comes from the sealed epoch, not from a tree rebuilt from the altered leaves.
func TestEventMerkleProofUsesSealedRoot(t *testing.T) {
	s := newAuditStore(t)
	addMerkleSchemaForTest(t, s)
	ids := seedKeyTrail(t, s, "t1")
	proof, err := s.GetEventMerkleProof(context.Background(), "t1", ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyProof(MerkleProof{LeafHash: proof.LeafHash, LeafIndex: proof.LeafIndex, Siblings: proof.Siblings, Root: proof.Root}) {
		t.Fatal("untouched proof does not verify")
	}
	mustExec(t, s, `UPDATE audit_merkle_leaves SET leaf_hash=$1 WHERE event_id=$2`, strings.Repeat("0", 64), ids[0])
	proof, err = s.GetEventMerkleProof(context.Background(), "t1", ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if VerifyProof(MerkleProof{LeafHash: proof.LeafHash, LeafIndex: proof.LeafIndex, Siblings: proof.Siblings, Root: proof.Root}) {
		t.Fatal("proof over an altered leaf verified")
	}
}

// The route emits audit.audit.target_integrity_verified with the verdict,
// and a tampered trail also raises the critical audit.audit.chain_broken.
func TestTargetIntegrityRouteAudited(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, false, false)
	stream := &loopbackPublisher{svc: svc}
	svc.publisher = stream
	addMerkleSchemaForTest(t, store)
	ids := seedKeyTrail(t, store, "t1")
	rec := &routetest.Recorder{}
	router := h.integrityRouter(rec)
	call := func() TargetIntegrity {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/audit/targets/key-1/integrity?tenant_id=t1", nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "auditor", TenantID: "t1", Permissions: []string{"audit.integrity.read"}}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			Integrity TargetIntegrity `json:"integrity"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Integrity
	}
	if got := call(); got.Verdict != "intact" {
		t.Fatalf("verdict %s", got.Verdict)
	}
	ev := rec.Last(t)
	if ev.Action != "target_integrity_verified" || ev.Event.TargetID != "key-1" || ev.Event.Details["verdict"] != "intact" {
		t.Fatalf("audited %+v", ev)
	}

	mustExec(t, store, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[1])
	if got := call(); got.Verdict != "tampered" {
		t.Fatalf("verdict %s", got.Verdict)
	}
	if ev := rec.Last(t); ev.Event.Details["verdict"] != "tampered" || ev.Event.Details["failed"] != 1 {
		t.Fatalf("audited %+v", ev)
	}
	broken, err := store.QueryEvents(context.Background(), "t1", EventQuery{Action: "audit.audit.chain_broken", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(broken) != 1 || broken[0].TargetID != "key-1" || broken[0].Details["scope"] != "target" {
		t.Fatalf("chain_broken events: %+v", broken)
	}
	if len(stream.subjects) != 1 || stream.subjects[0] != "audit.audit.chain_broken" {
		t.Fatalf("chain_broken was not published to the stream: %v", stream.subjects)
	}
}

func TestTargetIntegrityRouteRefusalsAudited(t *testing.T) {
	h, _, _, _ := newAuditHandler(t, false, false)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.integrityRouter(rec), rec)
}

// The same checks on real Postgres (CI integration-postgres): TIMESTAMPTZ
// and JSONB must round-trip to the bytes the chain hash was taken over, and
// an edit that bypasses the immutability trigger is still caught.
func TestTargetIntegrityPostgres(t *testing.T) {
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
	s := NewSQLStore(conn)
	tenant := "t-integrity-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	ids := checkIntactTrail(t, s, tenant)

	// The immutability trigger stops an ordinary edit.
	if _, err := s.db.SQL().Exec(`UPDATE audit_events SET actor_id='mallory' WHERE tenant_id=$1 AND id=$2`, tenant, ids[1]); err == nil {
		t.Fatal("audit_events accepted an update")
	}
	// A database superuser can bypass triggers; the proof must still catch it.
	tx, err := s.db.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SET LOCAL session_replication_role = replica`); err != nil {
		_ = tx.Rollback()
		t.Skipf("test role cannot bypass triggers: %v", err)
	}
	if _, err := tx.Exec(`UPDATE audit_events SET actor_id='mallory' WHERE tenant_id=$1 AND id=$2`, tenant, ids[1]); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	res, err := s.VerifyTarget(ctx, tenant, "key-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "tampered" || !containsString(eventResult(t, res, ids[1]).Failures, "content_altered") {
		t.Fatalf("tampering not detected on Postgres: %+v", res)
	}
}

func mustExec(t *testing.T, s *SQLStore, q string, args ...interface{}) {
	t.Helper()
	if _, err := s.db.SQL().Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func loadRow(t *testing.T, s *SQLStore, id string) AuditEvent {
	t.Helper()
	ev, err := scanChainRow(s.db.SQL().QueryRow(`SELECT `+chainRowColumns+` FROM audit_events WHERE id=$1`, id), "t1")
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

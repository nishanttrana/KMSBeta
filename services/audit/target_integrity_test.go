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

// seedKeyTrail writes, for tenant: other, key, key, other, key (covered by
// one signed checkpoint), then one more key event after it (pending). It
// returns the key's event IDs in write order.
func seedKeyTrail(t *testing.T, s *SQLStore, tenant string) []string {
	t.Helper()
	ctx := context.Background()
	s.SetEventSigningKey([]byte("0123456789abcdef0123456789abcdef"))
	base := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	var ids []string
	write := func(i int, target, action string) {
		ev, err := s.PersistEvent(ctx, AuditEvent{
			TenantID: tenant, Timestamp: base.Add(time.Duration(i) * time.Second), Service: "keycore", Action: action,
			ActorID: "alice", ActorType: "user", TargetType: "key", TargetID: target, Result: "success",
			Details: map[string]interface{}{"i": i},
		})
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
	if n, err := NewService(s, AuditConfig{}, nil, nil).SignCheckpoints(ctx); err != nil || n == 0 {
		t.Fatalf("sign checkpoint: %d %v", n, err)
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
		if e.Seal == integritySealed && (e.CheckpointID == "" || e.CheckpointSequence < e.Sequence) {
			t.Fatalf("sealed event %s names no covering checkpoint: %+v", e.EventID, e)
		}
	}
	if first := eventResult(t, res, ids[0]); first.Link != integrityLinked {
		t.Fatalf("first key event link = %s", first.Link)
	}
	return ids
}

func TestTargetIntegrityIntactTrail(t *testing.T) {
	s := newAuditStore(t)
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
			reasons: []string{"content_altered"},
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
			reasons: []string{"link_broken", "hmac_mismatch", "checkpoint_head_mismatch"},
		},
		{
			// An attacker holding the HMAC key rewrites the row and every
			// later hash and HMAC: links and HMACs pass, the signed head doesn't.
			name: "history rewritten with the HMAC key",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				rewriteChainFrom(t, s, "t1", ids[1], "mallory")
				return ids[1]
			},
			reasons: []string{"checkpoint_head_mismatch"},
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
			name: "checkpoint signature replaced",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				setCheckpointDetail(t, s, "signature", "MEUCIQDmallorymallorymallorymallorymallorymallorymalloryAAAA")
				return ids[0]
			},
			reasons: []string{"checkpoint_signature_invalid"},
		},
		{
			name: "checkpoint names an unregistered key",
			tamper: func(t *testing.T, s *SQLStore, ids []string) string {
				setCheckpointDetail(t, s, "key_id", strings.Repeat("A", 64))
				return ids[0]
			},
			reasons: []string{"checkpoint_key_unknown"},
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

// After a restart the store holds no key in memory: a checkpoint key is
// trusted only through its registration event, and only while that event's
// content and HMAC verify.
func TestCheckpointKeyTrustedOnlyThroughRegistration(t *testing.T) {
	s := newAuditStore(t)
	ids := seedKeyTrail(t, s, "t1")
	restarted := func() *SQLStore {
		r := NewSQLStore(s.db)
		r.SetEventSigningKey([]byte("0123456789abcdef0123456789abcdef"))
		return r
	}
	res, err := restarted().VerifyTarget(context.Background(), "t1", "key-1", 0)
	if err != nil || res.Verdict != "intact" || res.Sealed != 3 {
		t.Fatalf("after restart: %+v %v", res, err)
	}
	mustExec(t, s, `UPDATE audit_events SET hmac_sig=$1 WHERE action=$2`, strings.Repeat("0", 64), actionCheckpointKeyCreated)
	res, err = restarted().VerifyTarget(context.Background(), "t1", "key-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := eventResult(t, res, ids[0]); got.Seal != checkpointKeyUnknown || !containsString(got.Failures, "checkpoint_key_unknown") {
		t.Fatalf("key with a forged registration was trusted: %+v", got)
	}
}

// The route emits audit.audit.target_integrity_verified with the verdict,
// and a tampered trail also raises the critical audit.audit.chain_broken.
func TestTargetIntegrityRouteAudited(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, false, false)
	stream := &loopbackPublisher{svc: svc}
	svc.publisher = stream
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

// rewriteChainFrom sets actor_id on row id and recomputes the chain hash and
// HMAC of it and every later row of the tenant's chain, as an attacker
// holding the HMAC key could.
func rewriteChainFrom(t *testing.T, s *SQLStore, tenant, id, actor string) {
	t.Helper()
	rows, err := s.db.SQL().Query(`SELECT `+chainRowColumns+` FROM audit_events WHERE tenant_id=$1 ORDER BY sequence ASC`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	var evs []AuditEvent
	for rows.Next() {
		ev, err := scanChainRow(rows, tenant)
		if err != nil {
			t.Fatal(err)
		}
		evs = append(evs, ev)
	}
	_ = rows.Close()
	started, prev := false, ""
	for _, ev := range evs {
		if ev.ID == id {
			started = true
			ev.ActorID = actor
		} else if started {
			ev.PreviousHash = prev
		}
		if !started {
			continue
		}
		ev.ChainHash = chainHash(ev.PreviousHash, eventHashInput(ev))
		sig, _ := s.keys.sign(ev.ChainHash)
		mustExec(t, s, `UPDATE audit_events SET actor_id=$1, previous_hash=$2, chain_hash=$3, hmac_sig=$4 WHERE id=$5`,
			ev.ActorID, ev.PreviousHash, ev.ChainHash, sig, ev.ID)
		prev = ev.ChainHash
	}
}

// setCheckpointDetail edits one detail of tenant t1's checkpoint event.
func setCheckpointDetail(t *testing.T, s *SQLStore, key string, value interface{}) {
	t.Helper()
	var id string
	if err := s.db.SQL().QueryRow(`SELECT id FROM audit_events WHERE tenant_id='t1' AND action=$1`, actionCheckpointSigned).Scan(&id); err != nil {
		t.Fatal(err)
	}
	ev := loadRow(t, s, id)
	ev.Details[key] = value
	raw, err := json.Marshal(ev.Details)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE audit_events SET details=$1 WHERE id=$2`, string(raw), id)
}

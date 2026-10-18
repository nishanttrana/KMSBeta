package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

// GET /audit/chain/verify walked every row of a tenant's chains on every
// call: 78,196 rows for root took 15 to 20 seconds and then outran the
// 20-second limit (13.14.0-beta). It now walks each chain from its newest
// verified checkpoint; the hourly job keeps the full walk and records its
// pass. These tests pin what the quick walk catches, and what only the
// full walk does.

func breakReasons(res ChainVerification) map[string]bool {
	out := map[string]bool{}
	for _, b := range res.Breaks {
		out[b["reason"].(string)] = true
	}
	return out
}

func TestQuickWalkStartsAtTheNewestCheckpoint(t *testing.T) {
	s := newAuditStore(t)
	seedKeyTrail(t, s, "t1")
	ctx := context.Background()
	full, err := s.VerifyChainWalk(ctx, "t1", false)
	if err != nil || !full.OK || full.Scope != "full" {
		t.Fatalf("full walk: %+v %v", full, err)
	}
	quick, err := s.VerifyChainWalk(ctx, "t1", true)
	if err != nil || !quick.OK || quick.Scope != "since_checkpoint" {
		t.Fatalf("quick walk: %+v %v", quick, err)
	}
	self := s.chainNode(ctx)
	if quick.From[self] != 5 || quick.Rows >= full.Rows {
		t.Fatalf("quick walk from %v checked %d rows, full checked %d", quick.From, quick.Rows, full.Rows)
	}
}

func TestQuickWalkCatchesChangesAtAndAfterTheCheckpoint(t *testing.T) {
	cases := map[string]struct {
		tamper func(t *testing.T, s *SQLStore, ids []string)
		want   string
	}{
		// ids[2] is the signed head (sequence 5); ids[3] comes after it.
		"a row after the checkpoint": {func(t *testing.T, s *SQLStore, ids []string) {
			mustExec(t, s, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[3])
		}, "chain_hash_mismatch"},
		"the signed row's content": {func(t *testing.T, s *SQLStore, ids []string) {
			mustExec(t, s, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[2])
		}, "chain_hash_mismatch"},
		"the signed row removed": {func(t *testing.T, s *SQLStore, ids []string) {
			mustExec(t, s, `DELETE FROM audit_events WHERE id=$1`, ids[2])
		}, "checkpoint_head_mismatch"},
		"a rewrite by an HMAC key holder": {func(t *testing.T, s *SQLStore, ids []string) {
			rewriteChainFrom(t, s, "t1", ids[1], "mallory")
		}, "checkpoint_head_mismatch"},
		"a forged checkpoint": {func(t *testing.T, s *SQLStore, ids []string) {
			setCheckpointDetail(t, s, "chain_hash", "00")
		}, "checkpoint_signature_invalid"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := newAuditStore(t)
			ids := seedKeyTrail(t, s, "t1")
			tc.tamper(t, s, ids)
			res, err := s.VerifyChainWalk(context.Background(), "t1", true)
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || !breakReasons(res)[tc.want] {
				t.Fatalf("want %s, got %v", tc.want, res.Breaks)
			}
		})
	}
}

// What the quick walk does not recompute: the content of a row before the
// checkpoint, edited while its stored hash is left as it was. The signed
// hash still commits to it, and the full walk catches it.
func TestOnlyTheFullWalkRecomputesRowsBeforeTheCheckpoint(t *testing.T) {
	s := newAuditStore(t)
	ids := seedKeyTrail(t, s, "t1")
	mustExec(t, s, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, ids[0]) // sequence 2
	ctx := context.Background()
	if quick, err := s.VerifyChainWalk(ctx, "t1", true); err != nil || !quick.OK {
		t.Fatalf("the quick walk is documented not to see this: %+v %v", quick, err)
	}
	full, err := s.VerifyChainWalk(ctx, "t1", false)
	if err != nil || full.OK || !breakReasons(full)["chain_hash_mismatch"] {
		t.Fatalf("the full walk must: %+v %v", full, err)
	}
}

// A chain with no verified checkpoint is walked from its first row.
func TestQuickWalkWithoutACheckpointIsFull(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()
	var first string
	for i := 0; i < 3; i++ {
		ev, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t9", Service: "keycore", Action: "audit.key.encrypt", ActorID: "alice", ActorType: "user", Result: "success"})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = ev.ID
		}
	}
	mustExec(t, s, `UPDATE audit_events SET actor_id='mallory' WHERE id=$1`, first)
	res, err := s.VerifyChainWalk(ctx, "t9", true)
	if err != nil || res.OK || res.Rows != 3 {
		t.Fatalf("no checkpoint: %+v %v", res, err)
	}
}

func TestChainVerifyAPIQuickByDefaultAndReportsTheLastFullPass(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, true, true)
	seedKeyTrail(t, store, "t1")
	call := func(query string) map[string]interface{} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/audit/chain/verify?tenant_id=t1"+query, nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", Permissions: []string{"*"}}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d %s", rr.Code, rr.Body.String())
		}
		var out map[string]interface{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out
	}
	quick := call("")
	if quick["scope"] != "since_checkpoint" || quick["ok"] != true || quick["last_full_verification"] != nil {
		t.Fatalf("default: %v", quick)
	}
	ctx := context.Background()
	full, err := svc.VerifyChainWalk(ctx, "t1", false)
	if err != nil || !full.OK {
		t.Fatal(full, err)
	}
	svc.RecordFullVerification(ctx, "t1", full, time.Second)
	if got := call(""); got["last_full_verification"] == nil {
		t.Fatalf("the hourly full pass must be reported: %v", got)
	}
	if got := call("&full=true"); got["scope"] != "full" || got["ok"] != true {
		t.Fatalf("full=true: %v", got)
	}
	rows, _ := store.QueryEvents(ctx, "t1", EventQuery{Action: actionChainVerified, Limit: 5})
	if len(rows) != 1 || rows[0].Result != "success" {
		t.Fatalf("chain_verified events: %+v", rows)
	}
}

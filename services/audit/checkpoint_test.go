package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route/routetest"
)

// A checkpoint is signed only for a chain that moved since its last one; the
// first run also records the key (root) and signs that chain.
func TestSignCheckpointsSignsMovedChainsOnly(t *testing.T) {
	s := newAuditStore(t)
	seedKeyTrail(t, s, "t1") // signs t1 and root once
	svc := NewService(s, AuditConfig{}, nil, nil)
	ctx := context.Background()
	n, err := svc.SignCheckpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// A new process: a new key registered under root, t1 moved after the
	// seed's checkpoint (one pending event), root moved (the new key).
	if n != 2 {
		t.Fatalf("signed %d, want 2", n)
	}
	if n, err := svc.SignCheckpoints(ctx); err != nil || n != 0 {
		t.Fatalf("idle chains re-signed: %d %v", n, err)
	}
	if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t1", Service: "keycore", Action: "audit.key.encrypt", ActorID: "alice", ActorType: "user", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if n, err := svc.SignCheckpoints(ctx); err != nil || n != 1 {
		t.Fatalf("moved chain: signed %d %v", n, err)
	}
	keys, err := s.QueryEvents(ctx, "root", EventQuery{Action: actionCheckpointKeyCreated, Limit: 10})
	if err != nil || len(keys) != 2 {
		t.Fatalf("key registrations %d %v", len(keys), err)
	}
	if keys[0].Details["algorithm"] != pkgcrypto.AlgECDSAP384 || keys[0].Details["public_key_pem"] == "" {
		t.Fatalf("registration %+v", keys[0].Details)
	}
}

// What the API returns is enough for an outside verifier: the exact signed
// message, the signature and the public key.
func TestCheckpointVerifiesOutsideTheService(t *testing.T) {
	s := newAuditStore(t)
	seedKeyTrail(t, s, "t1")
	items, err := s.ListCheckpoints(context.Background(), "t1", 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("checkpoints %d %v", len(items), err)
	}
	cp := items[0]
	if cp.Status != checkpointVerified || cp.Sequence != 5 || cp.Algorithm != pkgcrypto.AlgECDSAP384 {
		t.Fatalf("checkpoint %+v", cp)
	}
	pub, err := pkgcrypto.ParsePublicKeyPEM(cp.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(cp.Signature)
	if err := pkgcrypto.Verify(pkgcrypto.AlgECDSAP384, pub, []byte(cp.Message), sig); err != nil {
		t.Fatalf("signature does not verify outside the service: %v", err)
	}
	var head checkpointHead
	if err := json.Unmarshal([]byte(cp.Message), &head); err != nil || head.ChainHash != cp.ChainHash || head.TenantID != "t1" {
		t.Fatalf("message %s", cp.Message)
	}
}

// A signing failure is refused and audited, and nothing is recorded as signed.
func TestCheckpointRefusalAudited(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()
	if _, err := s.PersistEvent(ctx, AuditEvent{TenantID: "t1", Service: "keycore", Action: "audit.key.encrypt", ActorID: "alice", ActorType: "user", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	svc := NewService(s, AuditConfig{}, nil, nil)
	svc.checkpoints.signer = &checkpointSigner{keyID: "k", sign: func([]byte) ([]byte, error) { return nil, errors.New("entropy source failed") }}
	if n, err := svc.SignCheckpoints(ctx); err != nil || n != 0 {
		t.Fatalf("signed %d %v", n, err)
	}
	got, err := s.QueryEvents(ctx, "t1", EventQuery{Action: actionCheckpointRefused, Limit: 5})
	if err != nil || len(got) != 1 || got[0].Result != "refused" || got[0].Details["reason"] != "signing_failed" {
		t.Fatalf("refusal events %+v %v", got, err)
	}
	if signed, _ := s.QueryEvents(ctx, "t1", EventQuery{Action: actionCheckpointSigned, Limit: 5}); len(signed) != 0 {
		t.Fatalf("a checkpoint was recorded: %+v", signed)
	}
}

// A rewrite by someone holding the HMAC key passes every link and HMAC; the
// whole-chain check still catches it at the signed head.
func TestVerifyChainCatchesRewriteWithHMACKey(t *testing.T) {
	s := newAuditStore(t)
	ids := seedKeyTrail(t, s, "t1")
	ctx := context.Background()
	if ok, breaks, err := s.VerifyChain(ctx, "t1"); err != nil || !ok {
		t.Fatalf("untouched chain: %v %v", breaks, err)
	}
	rewriteChainFrom(t, s, "t1", ids[1], "mallory")
	ok, breaks, err := s.VerifyChain(ctx, "t1")
	if err != nil || ok {
		t.Fatalf("rewrite not detected: %v %v", breaks, err)
	}
	if len(breaks) != 1 || breaks[0]["reason"] != "checkpoint_head_mismatch" {
		t.Fatalf("breaks %v", breaks)
	}
}

// A removed head row, and a tampered checkpoint, are chain breaks.
func TestVerifyChainChecksCheckpoints(t *testing.T) {
	cases := map[string]func(t *testing.T, s *SQLStore, ids []string){
		"checkpoint_head_mismatch": func(t *testing.T, s *SQLStore, ids []string) {
			mustExec(t, s, `DELETE FROM audit_events WHERE id=$1`, ids[2]) // the signed head (sequence 5)
		},
		"checkpoint_signature_invalid": func(t *testing.T, s *SQLStore, ids []string) {
			setCheckpointDetail(t, s, "chain_hash", "00")
		},
	}
	for want, tamper := range cases {
		t.Run(want, func(t *testing.T) {
			s := newAuditStore(t)
			ids := seedKeyTrail(t, s, "t1")
			tamper(t, s, ids)
			_, breaks, err := s.VerifyChain(context.Background(), "t1")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, b := range breaks {
				found = found || b["reason"] == want
			}
			if !found {
				t.Fatalf("breaks %v, want %s", breaks, want)
			}
		})
	}
}

// GET /audit/checkpoints emits audit.audit.checkpoints_listed; a checkpoint
// that fails verification also raises audit.audit.chain_broken.
func TestCheckpointsRouteAudited(t *testing.T) {
	h, svc, store, _ := newAuditHandler(t, false, false)
	stream := &loopbackPublisher{svc: svc}
	svc.publisher = stream
	seedKeyTrail(t, store, "t1")
	rec := &routetest.Recorder{}
	router := h.integrityRouter(rec)
	call := func() []CheckpointStatus {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/audit/checkpoints?tenant_id=t1", nil)
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "auditor", TenantID: "t1", Permissions: []string{"audit.integrity.read"}}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var body struct {
			Items []CheckpointStatus `json:"items"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Items
	}
	if items := call(); len(items) != 1 || items[0].Status != checkpointVerified {
		t.Fatalf("items %+v", items)
	}
	if ev := rec.Last(t); ev.Action != "checkpoints_listed" || ev.Event.Details["failed"] != 0 {
		t.Fatalf("audited %+v", ev)
	}
	setCheckpointDetail(t, store, "signature", base64.StdEncoding.EncodeToString([]byte("forged")))
	if items := call(); items[0].Status != checkpointBadSignature {
		t.Fatalf("items %+v", items)
	}
	if ev := rec.Last(t); ev.Event.Details["failed"] != 1 {
		t.Fatalf("audited %+v", ev)
	}
	if len(stream.subjects) != 1 || stream.subjects[0] != "audit.audit.chain_broken" {
		t.Fatalf("chain_broken was not published: %v", stream.subjects)
	}
}

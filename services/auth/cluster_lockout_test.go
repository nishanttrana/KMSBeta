package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vecta-kms/pkg/clusterstate"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/metering"
)

func tryLogin(h *Handler, user, password string) int {
	raw, _ := json.Marshal(map[string]any{"tenant_id": "t1", "username": user, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.7:4444"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// Two nodes share the replicated auth_login_attempts table (one database here).
// Failures spread across them lock the key on both; each node's in-memory
// limiter alone would not.
func TestLockoutCountsFailuresAcrossClusterNodes(t *testing.T) {
	nodeA, _, store, pubA := newTestHandler(t)
	key, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	pubB := &mockPublisher{}
	nodeB := NewHandler(store, NewAuthLogic(key, "test-issuer", "test-aud"), pubB, metering.NewMeter(0, time.Hour), nil)

	// Standalone: nothing is recorded, so each node counts alone.
	for i := 0; i < 3; i++ {
		tryLogin(nodeA, "mallory", "guess")
	}
	if n, _ := store.RecentLoginAttempts(context.Background(), lockoutKeyHash("t1|mallory|203.0.113.7"), time.Now().Add(-time.Hour), 10); len(n) != 0 {
		t.Fatal("a standalone node must not record attempts in the shared table")
	}

	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n1", Role: clusterstate.RolePrimary}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })

	// Default policy: 5 failures. 3 on A, 2 on B: neither node reaches 5 alone.
	for i := 0; i < 3; i++ {
		if code := tryLogin(nodeA, "eve", "guess"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d on A: %d", i, code)
		}
	}
	for i := 0; i < 2; i++ {
		if code := tryLogin(nodeB, "eve", "guess"); code != http.StatusUnauthorized {
			t.Fatalf("failure %d on B: %d", i, code)
		}
	}
	for name, h := range map[string]*Handler{"A": nodeA, "B": nodeB} {
		if code := tryLogin(h, "eve", "guess"); code != http.StatusTooManyRequests {
			t.Fatalf("node %s must refuse a key locked by failures across the cluster, got %d", name, code)
		}
	}
	locked := 0
	for _, s := range append(pubA.subjects, pubB.subjects...) {
		if s == "audit.auth.account_locked" {
			locked++
		}
	}
	if locked != 2 {
		t.Fatalf("each cluster lockout refusal must be audited, got %d", locked)
	}

	// A success recorded on any node clears the count.
	if err := store.RecordLoginAttempt(context.Background(), LoginAttempt{
		ID: "lat_ok", ChainNode: "n2", TenantID: "t1", KeyHash: lockoutKeyHash("t1|frank|203.0.113.7"), Succeeded: true, OccurredAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, locked := nodeA.clusterLocked(context.Background(), "t1|frank|203.0.113.7", 5, 15*time.Minute, time.Now().UTC()); locked {
		t.Fatal("a key with no failures after its last success must not be locked")
	}
}

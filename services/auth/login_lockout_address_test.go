package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vecta-kms/pkg/clientip"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/metering"
)

// The lockout counts a guesser's failures however each request is dressed.
// Until 11.8.0-beta the address in the lockout key was the first
// X-Forwarded-For entry, which the caller writes: a different value on every
// guess gave every guess a fresh counter, and the lockout never came.
func TestLockoutIgnoresTheAddressTheCallerWrites(t *testing.T) {
	_, _, store, _ := newTestHandler(t)
	key, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := &payloadPublisher{}
	h := NewHandler(store, NewAuthLogic(key, "test-issuer", "test-aud"), pub, metering.NewMeter(0, time.Hour), nil)

	// The edge appends the address it saw after whatever the caller sent.
	guess := func(user, forwarded string) int {
		raw, _ := json.Marshal(map[string]any{"tenant_id": "t1", "username": user, "password": "guess"})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(raw))
		req.RemoteAddr = "172.18.0.9:41000" // the edge proxy
		req.Header.Set(clientip.Header, forwarded)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	// Default policy: five failures lock the key.
	for i := 0; i < 5; i++ {
		if code := guess("mallory", fmt.Sprintf("10.9.%d.1, 198.51.100.7", i)); code != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i+1, code)
		}
	}
	if code := guess("mallory", "10.9.99.1, 198.51.100.7"); code != http.StatusTooManyRequests {
		t.Fatalf("a sixth guess claiming yet another address must be locked out, got %d", code)
	}
	for _, subject := range []string{"audit.auth.account_locked", "audit.auth.login_failed"} {
		ev, ok := pub.last(subject)
		if !ok || eventData(ev)["source_ip"] != "198.51.100.7" {
			t.Fatalf("%s must be audited with the address the edge saw: %+v", subject, ev)
		}
	}

	// Claiming the locked-out address does not lock out somebody else: the
	// same user from another real address still gets an answer.
	if code := guess("mallory", "198.51.100.7, 198.51.100.8"); code != http.StatusUnauthorized {
		t.Fatalf("a caller the edge saw elsewhere must not inherit the lockout by naming it, got %d", code)
	}
}

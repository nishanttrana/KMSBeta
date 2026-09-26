package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"vecta-kms/pkg/internalauth"
	"vecta-kms/pkg/servicetoken"
)

// Keycore decides key access from a verified token, so the reconciler's
// lifecycle calls carry the kms-reconciler service JWT (plus the internal
// token for internalauth routes) and name the key's tenant.
func TestLifecycleCallsCarryServiceIdentityAndTenant(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "reconciler-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	t.Setenv(internalauth.EnvVar, "internal-test-token")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-reconciler"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	var mu sync.Mutex
	var rotate *http.Request
	keycore := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/keys/due-for-lifecycle":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]string{
				{"tenant_id": "tenant-a", "key_id": "k1", "action": "rotate", "reason": "cryptoperiod"},
			}})
		case "/keys/k1/rotate":
			mu.Lock()
			rotate = r.Clone(context.Background())
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer keycore.Close()

	r := newKeyLifecycleReconciler(keycore.Client(), keycore.URL, log.Default())
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if rotate == nil {
		t.Fatal("rotate was not called")
	}
	if got := rotate.Header.Get("Authorization"); got != "Bearer reconciler-jwt" {
		t.Fatalf("Authorization = %q, want the reconciler service token", got)
	}
	if rotate.Header.Get(internalauth.HeaderName) != "internal-test-token" {
		t.Fatal("internal token missing")
	}
	if rotate.URL.Query().Get("tenant_id") != "tenant-a" {
		t.Fatalf("tenant_id = %q", rotate.URL.Query().Get("tenant_id"))
	}
}

package keyaccess

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/servicetoken"
)

// Evaluate carries the calling service's JWT. Until 6.9.0-beta it sent no
// Authorization header, so keyaccess (behind its JWT middleware) answered 401
// to every evaluation and the callers fell back to their unavailable path.
func TestEvaluateSendsServiceToken(t *testing.T) {
	secret, err := pkgcrypto.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "svc-token-probe", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
	}))
	defer auth.Close()
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", hex.EncodeToString(secret))
	t.Setenv("AUTH_URL", auth.URL)
	servicetoken.SetDefault(servicetoken.FromEnv("kms-ekm"))
	defer servicetoken.SetDefault(nil)

	var got string
	ka := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"action": "allow"}})
	}))
	defer ka.Close()
	out, err := NewHTTPClient(ka.URL, time.Second).Evaluate(context.Background(), EvaluateRequest{TenantID: "t1", Operation: "decrypt"})
	if err != nil || out.Action != "allow" {
		t.Fatalf("evaluate: %+v %v", out, err)
	}
	if got != "Bearer svc-token-probe" {
		t.Fatalf("Authorization %q, want the service token", got)
	}
}

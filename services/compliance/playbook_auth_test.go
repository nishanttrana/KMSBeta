package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"vecta-kms/pkg/servicetoken"
)

// headerCatcher records the Authorization header of every request it serves.
type headerCatcher struct {
	mu   sync.Mutex
	seen map[string]string // path -> Authorization
}

func (c *headerCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	if c.seen == nil {
		c.seen = map[string]string{}
	}
	c.seen[r.URL.Path] = r.Header.Get("Authorization")
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

func (c *headerCatcher) auth(path string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.seen[path]
	return v, ok
}

// Keycore refuses anonymous key use, so playbook key actions call it as the
// compliance service identity, and that token never goes anywhere else.
func TestPlaybookSendsServiceTokenOnlyToPlatformServices(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/client-token" || r.Header.Get("X-API-Key") == "" {
			http.Error(w, "bad mint", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "svc-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-compliance"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	keycore, external := &headerCatcher{}, &headerCatcher{}
	keycoreSrv, externalSrv := httptest.NewServer(keycore), httptest.NewServer(external)
	defer keycoreSrv.Close()
	defer externalSrv.Close()

	e := NewPlaybookExecutor(nil, keycoreSrv.URL, "http://certs.invalid", "http://policy.invalid", "http://audit.invalid", nil, log.Default())
	ctx := context.Background()
	if err := e.actionRotateKey(ctx, map[string]string{"key_id": "k1"}, RunContext{TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := keycore.auth("/keys/k1/rotate"); got != "Bearer svc-jwt" {
		t.Fatalf("keycore call carried %q, want the service token", got)
	}
	if err := e.actionSendWebhook(ctx, map[string]string{"url": externalSrv.URL + "/hook"}); err != nil {
		t.Fatal(err)
	}
	if err := e.doPost(ctx, externalSrv.URL+"/api/now/table/incident", map[string]string{"x": "y"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/hook", "/api/now/table/incident"} {
		if got, ok := external.auth(path); !ok || got != "" {
			t.Fatalf("external %s received Authorization %q (seen=%v)", path, got, ok)
		}
	}
}

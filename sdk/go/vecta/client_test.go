package vecta

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, []byte) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestNewRefusesBadConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"http":       {BaseURL: "http://kms.example.com", TenantID: "t", Token: "x"},
		"no tenant":  {BaseURL: "https://kms.example.com", Token: "x"},
		"no creds":   {BaseURL: "https://kms.example.com", TenantID: "t"},
		"bad ttl":    {BaseURL: "https://kms.example.com", TenantID: "t", Token: "x", TokenTTL: time.Second},
		"bad ca":     {BaseURL: "https://kms.example.com", TenantID: "t", Token: "x", CAPEM: []byte("nope")},
		"key, no id": {BaseURL: "https://kms.example.com", TenantID: "t", APIKey: "k"},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// The client exchanges its API key for a token once, reuses it, renews it
// once when the KMS answers 401, and reports the KMS's refusal as an
// APIError with its reason.
func TestTokenExchangeAndErrors(t *testing.T) {
	var exchanges, calls atomic.Int32
	srv, ca := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/svc/auth/auth/client-token":
			if r.Header.Get("X-API-Key") != "api-key" {
				w.WriteHeader(401)
				return
			}
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["client_id"] != "release" || in["tenant_id"] != "acme" || in["ttl_seconds"] != float64(300) {
				t.Errorf("exchange body %v", in)
			}
			n := exchanges.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + string(rune('0'+n)), "expires_at": time.Now().Add(5 * time.Minute)})
		case r.URL.Path == "/svc/keycore/keys/k1":
			c := calls.Add(1)
			if r.URL.Query().Get("tenant_id") != "acme" || r.Header.Get("X-Tenant-ID") != "acme" {
				t.Errorf("tenant missing: %s", r.URL)
			}
			if c == 2 && r.Header.Get("Authorization") == "Bearer tok-1" {
				w.WriteHeader(401) // the KMS no longer accepts the first token
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{"id": "k1", "algorithm": "AES-256", "current_version": 2}})
		default:
			w.WriteHeader(403)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "no_matching_grant", "message": "access denied", "request_id": "req_1"}})
		}
	})
	c, err := New(Config{BaseURL: srv.URL, TenantID: "acme", ClientID: "release", APIKey: "api-key", CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		k, err := c.GetKey(ctx, "k1")
		if err != nil || k.Algorithm != "AES-256" || k.CurrentVersion != 2 {
			t.Fatalf("get %d: %+v %v", i, k, err)
		}
	}
	if exchanges.Load() != 2 {
		t.Fatalf("exchanges: %d (one, then one renewal after the 401)", exchanges.Load())
	}
	_, err = c.Encrypt(ctx, "k2", []byte("x"), nil)
	if !IsRefused(err) || IsNotFound(err) {
		t.Fatalf("refusal: %v", err)
	}
	var ae *APIError
	if !strings.Contains(err.Error(), "no_matching_grant") || !strings.Contains(err.Error(), "req_1") || !errors.As(err, &ae) || ae.Code != "no_matching_grant" {
		t.Fatalf("APIError: %v", err)
	}

	// The system roots don't trust the test server: TLS is verified.
	plain, _ := New(Config{BaseURL: srv.URL, TenantID: "acme", Token: "x"})
	if _, err := plain.GetKey(ctx, "k1"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("an unverified server was trusted: %v", err)
	}
}

// ListKeys follows the cursor across pages and stops when asked.
func TestListKeysPages(t *testing.T) {
	srv, ca := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("after_id") == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "a"}, {"id": "b"}}, "has_more": true,
				"next_cursor": map[string]any{"after_created_at": "2026-10-23T00:00:00Z", "after_id": "b"}})
			return
		}
		if r.URL.Query().Get("after_id") != "b" || r.URL.Query().Get("after_created_at") != "2026-10-23T00:00:00Z" {
			t.Errorf("cursor: %s", r.URL)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": "c"}}, "has_more": false})
	})
	c, err := New(Config{BaseURL: srv.URL, TenantID: "acme", Token: "static", CAPEM: ca})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	if err := c.ListKeys(context.Background(), func(k Key) bool { ids = append(ids, k.ID); return true }); err != nil || strings.Join(ids, ",") != "a,b,c" {
		t.Fatalf("ids %v %v", ids, err)
	}
	ids = nil
	_ = c.ListKeys(context.Background(), func(k Key) bool { ids = append(ids, k.ID); return len(ids) < 1 })
	if len(ids) != 1 {
		t.Fatalf("stop: %v", ids)
	}
}

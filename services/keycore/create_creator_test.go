package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/tenantcheck"
)

// A key's creator is who created it. Until 13.0.0-beta created_by was taken
// from the body: the record of who made a key, and the creator's standing
// over it, went to whoever the caller named. Only a platform service may
// name the person it creates a key for.
func TestKeyCreatorIsTheVerifiedCaller(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TENANT", "root")
	h, svc, _ := newActorTestHandler(t)
	create := func(name string, claims *pkgauth.Claims) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"tenant_id": "t1", "name": name, "algorithm": "AES-256", "key_type": "symmetric", "purpose": "encrypt",
			"created_by": "somebody-else",
		})
		req := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(body))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, w.Code, w.Body)
		}
		var out struct {
			KeyID string `json:"key_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		key, err := svc.GetKey(context.Background(), "t1", out.KeyID)
		if err != nil {
			t.Fatal(err)
		}
		return key.CreatedBy
	}
	if by := create("a-persons", &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "u-7", Permissions: []string{"*"}}); by != "u-7" {
		t.Fatalf("a person's key: created_by = %q, want the caller u-7", by)
	}
	service := &pkgauth.Claims{TenantID: tenantcheck.InternalServiceTenant(), Role: "client-service", ClientID: "kms-autokey", Permissions: []string{"service.internal"}}
	if by := create("a-services", service); by != "somebody-else" {
		t.Fatalf("a platform service names who it creates the key for: created_by = %q", by)
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vecta-kms/pkg/internalauth"
)

// The reconciler's KMIP auto-decommission judged "no traffic" from the
// client row's updated_at, which KMIP traffic never touches, so every client
// went dormant (refused by ConnectHook) 90 days after it was created. The
// routes are gone (5.3.0-beta): the internal token no longer changes a
// client's status.
func TestDecommissionRoutesRemoved(t *testing.T) {
	t.Setenv(internalauth.EnvVar, "internal-test-token")
	h := (&Handler{}).HTTPHandler()
	req := httptest.NewRequest(http.MethodPost, "/kmip/clients/c1/decommission", strings.NewReader(`{"action":"revoke","tenant_id":"t1"}`))
	req.Header.Set(internalauth.HeaderName, "internal-test-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("POST /kmip/clients/{id}/decommission: %d, want 404", w.Code)
	}
}

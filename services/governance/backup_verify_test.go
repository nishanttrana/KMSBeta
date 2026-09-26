package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// The verify route is root-admin only, and it names the caller from the
// verified token: a created_by in the body is ignored.
func TestVerifyBackupRouteAuthAndActor(t *testing.T) {
	h, pub := newAuthTestHandler(t)
	call := func(claims *pkgauth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/governance/backups/verify?tenant_id=root",
			strings.NewReader(`{"artifact_file_name":"x.vbk","artifact_content_base64":"","key_file_name":"x.key.json","created_by":"forged-actor"}`))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	if rr := call(&pkgauth.Claims{TenantID: "root", Role: "viewer", UserID: "v1"}); rr.Code != http.StatusForbidden {
		t.Fatalf("viewer: %d, want 403 (%s)", rr.Code, rr.Body)
	}
	if d := lastRefusal(t, pub, "audit.governance.system_admin_refused"); d["reason"] != "insufficient_privileges" {
		t.Fatalf("viewer refusal: %+v", d)
	}

	if rr := call(&pkgauth.Claims{TenantID: "root", Role: "admin", UserID: "root-admin"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("admin with an empty artifact: %d, want 400 (%s)", rr.Code, rr.Body)
	}
	d := lastRefusal(t, pub, "audit.governance.backup_verify_refused")
	if d["requested_by"] != "root-admin" || d["result"] != "refused" {
		t.Fatalf("verify refusal must name the verified caller, not the body: %+v", d)
	}
}

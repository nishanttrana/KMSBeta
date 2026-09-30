package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func TestDataProtectRoutesRefusalsAudited(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, NewHandler(svc, rec).router, rec)
}

// Before 7.4.0-beta any verified token could change the data protection
// policy, delete vaults or detokenize: no route checked a permission.
func TestDataProtectRoutesNeedTheirPermission(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec)
	readonly := &pkgauth.Claims{UserID: "ro", TenantID: "t1", Role: "readonly", Permissions: []string{"dataprotect.read"}}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/detokenize", `{"tenant_id":"t1","tokens":["x"]}`},
		{http.MethodPut, "/policy", `{"tenant_id":"t1"}`},
		{http.MethodDelete, "/token-vaults/v1?tenant_id=t1", ``},
		{http.MethodPost, "/field-encryption/register/complete", `{"tenant_id":"t1","governance_approved":true}`},
		// A wrapper runtime route without a wrapper token needs the permission too.
		{http.MethodPost, "/field-encryption/leases", `{"tenant_id":"t1"}`},
	} {
		rec.Reset()
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), readonly)))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s as dataprotect.read: %d %s", c.method, c.path, rr.Code, rr.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != route.ReasonPermissionDenied {
			t.Fatalf("%s %s audited as %s %+v", c.method, c.path, ev.Action, ev.Event.Details)
		}
	}
}

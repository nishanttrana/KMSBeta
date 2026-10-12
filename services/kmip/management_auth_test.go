package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// Every route of the management API refuses a caller without a token,
// without the permission, or naming another tenant, and audits the refusal.
func TestManagementRoutesRefuseAndAudit(t *testing.T) {
	h, _, _ := newKMIPHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.HTTPRouter(rec, nil), rec)
}

// oneCA answers the certs service's CA listing with a CA for whichever
// tenant asks, so a profile can name it.
type oneCA struct{}

func (oneCA) ListCAs(_ context.Context, tenantID string) ([]CertsCA, error) {
	return []CertsCA{{ID: "ca-1", TenantID: tenantID, Name: "issuing"}}, nil
}

func (oneCA) IssueCertificate(context.Context, CertsIssueCertificateRequest) (CertsIssuedCertificate, error) {
	return CertsIssuedCertificate{}, errors.New("not used here")
}

// The management API registers KMIP clients and hands out their
// certificates. Until 13.0.0-beta its server verified no token: a request
// with none listed a tenant's clients and profiles and could add to them.
func TestManagementAPINeedsATokenAndTheCallersTenant(t *testing.T) {
	h, _, _ := newKMIPHandler(t)
	h.certs = oneCA{}
	rec := &routetest.Recorder{}
	rt := h.HTTPRouter(rec, nil)
	call := func(method, target, body string, claims *pkgauth.Claims) (*httptest.ResponseRecorder, map[string]interface{}) {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		if claims != nil {
			req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		}
		w := httptest.NewRecorder()
		rt.ServeHTTP(w, req)
		out := map[string]interface{}{}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}
	admin := func(tenant string) *pkgauth.Claims {
		return &pkgauth.Claims{UserID: "admin-" + tenant, TenantID: tenant, Role: "admin", Permissions: []string{"*"}}
	}
	profile := `{"tenant_id":"t1","name":"storage","ca_id":"ca-1","role":"kmip-client"}`

	// No token: nothing is listed and nothing is created.
	for _, c := range []struct{ method, target, body string }{
		{http.MethodGet, "/kmip/clients?tenant_id=t1", ""},
		{http.MethodGet, "/kmip/profiles?tenant_id=t1", ""},
		{http.MethodGet, "/kmip/interop/targets?tenant_id=t1", ""},
		{http.MethodGet, "/kmip/capabilities?tenant_id=t1", ""},
		{http.MethodPost, "/kmip/profiles", profile},
		{http.MethodPost, "/kmip/clients", `{"tenant_id":"t1","name":"intruder","profile_id":"p1","enrollment_mode":"internal"}`},
		{http.MethodDelete, "/kmip/clients/c1?tenant_id=t1", ""},
	} {
		w, _ := call(c.method, c.target, c.body, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token: %d, want 401", c.method, c.target, w.Code)
		}
		if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != route.ReasonUnauthenticated {
			t.Fatalf("%s %s: refusal not audited: %+v", c.method, c.target, ev)
		}
	}

	// A tenant's administrator manages its own profiles.
	w, out := call(http.MethodPost, "/kmip/profiles", profile, admin("t1"))
	if w.Code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", w.Code, w.Body)
	}
	id := out["profile"].(map[string]interface{})["id"].(string)
	if ev := rec.Last(t); ev.Action != "profile_create" || ev.Event.ActorID != "admin-t1" || ev.Event.TenantID != "t1" || ev.Event.Result != route.ResultSuccess {
		t.Fatalf("create audit: %+v", ev)
	}
	if w, out := call(http.MethodGet, "/kmip/profiles?tenant_id=t1", "", admin("t1")); w.Code != http.StatusOK || len(out["items"].([]interface{})) != 1 {
		t.Fatalf("own profiles: %d %s", w.Code, w.Body)
	}

	// Another tenant's administrator can't read, add to or delete them,
	// however the tenant is named.
	for _, c := range []struct{ method, target, body string }{
		{http.MethodGet, "/kmip/profiles?tenant_id=t1", ""},
		{http.MethodPost, "/kmip/profiles", profile},
		{http.MethodPost, "/kmip/profiles?tenant_id=t2", profile},
		{http.MethodDelete, "/kmip/profiles/" + id + "?tenant_id=t1", ""},
	} {
		if w, _ := call(c.method, c.target, c.body, admin("t2")); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s as another tenant: %d, want 403", c.method, c.target, w.Code)
		}
	}
	// Asking for its own tenant, it sees none of t1's.
	if w, out := call(http.MethodGet, "/kmip/profiles?tenant_id=t2", "", admin("t2")); w.Code != http.StatusOK || len(out["items"].([]interface{})) != 0 {
		t.Fatalf("another tenant's view: %d %s", w.Code, w.Body)
	}
	// A signed-in user without the permission is refused too.
	reader := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "auditor", Permissions: []string{"kmip.read"}}
	if w, _ := call(http.MethodDelete, "/kmip/profiles/"+id+"?tenant_id=t1", "", reader); w.Code != http.StatusForbidden {
		t.Fatalf("delete with read permission: %d, want 403", w.Code)
	}
	if w, _ := call(http.MethodGet, "/kmip/profiles?tenant_id=t1", "", reader); w.Code != http.StatusOK {
		t.Fatalf("read with read permission: %d", w.Code)
	}
}

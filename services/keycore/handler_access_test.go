package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func TestAccessRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.accessRouter(rec), rec)
}

func TestKeyAdminRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.keyAdminRouter(rec), rec)
}

// managementCalls are the writes that, before 4.0.0-beta, any caller could
// make: without a token, or with a readonly user's token.
func managementCalls(keyID string) []struct{ method, path, body string } {
	return []struct{ method, path, body string }{
		{http.MethodPut, "/keys/" + keyID + "/export-policy", `{"export_allowed":true}`},
		{http.MethodPut, "/keys/" + keyID + "/access-policy", `{"grants":[{"subject_type":"user","subject_id":"mallory","operations":["all"]}]}`},
		{http.MethodPut, "/keys/" + keyID + "/approval", `{"required":false}`},
		{http.MethodPost, "/keys/" + keyID + "/destroy", `{}`},
		{http.MethodPost, "/keys/" + keyID + "/rotate", `{}`},
		{http.MethodPut, "/access/settings", `{"deny_by_default":false}`},
		{http.MethodPost, "/access/groups", `{"name":"g"}`},
		{http.MethodPost, "/access/interface-ports", `{"interface_name":"rest"}`},
		{http.MethodPost, "/keys", `{"name":"k","algorithm":"AES-256"}`},
	}
}

func callKeycore(h *Handler, method, path, body string, claims *pkgauth.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path+"?tenant_id=t1", bytes.NewBufferString(body))
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// A request without a verified token is refused before any handler runs and
// audited as audit.key.request_refused; nothing changes.
func TestTokenlessManagementRequestsAreRefused(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := ownedKey(t, svc)
	for _, c := range managementCalls(key.ID) {
		if w := callKeycore(h, c.method, c.path, c.body, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token: %d, want 401 (%s)", c.method, c.path, w.Code, w.Body)
		}
		if d := refusalDetails(t, rec, "audit.key.request_refused"); d["reason"] != "unauthenticated" || d["path"] != c.path {
			t.Fatalf("%s %s: refusal details %+v", c.method, c.path, d)
		}
	}
	got, err := svc.GetKey(t.Context(), "t1", key.ID)
	if err != nil || got.ExportAllowed || isDeletedLike(got.Status) {
		t.Fatalf("tokenless requests changed the key: %+v %v", got, err)
	}
}

// Only the internal-token route is reachable without a JWT, and it still
// demands its own token. The no-op /tenants/onboard and the archive stub are
// gone (5.3.0-beta), so without a JWT they meet the gate like any route.
func TestTokenlessRoutesAreOnlyTheDeclaredOnes(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	t.Setenv("INTERNAL_API_TOKEN", "")
	if w := callKeycore(h, http.MethodGet, "/keys/due-for-lifecycle", "", nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("internal route reached the JWT gate instead of internalauth: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/tenants/onboard", "/keys/k1/archive"} {
		if w := callKeycore(h, http.MethodPost, path, "{}", nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("POST %s without a token: %d, want 401", path, w.Code)
		}
	}
	if w := callKeycore(h, http.MethodGet, "/keys", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /keys without a token: %d, want 401", w.Code)
	}
}

// A verified token without the permission is refused by the kernel, audited
// under the route's action with reason permission_denied.
func TestReadonlyUserCannotManageKeys(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key := ownedKey(t, svc)
	readonly := &pkgauth.Claims{UserID: "ro-user", TenantID: "t1", Role: "readonly", Permissions: []string{"auth.self.read", "auth.user.read"}}
	for _, c := range managementCalls(key.ID) {
		rec.Reset()
		if w := callKeycore(h, c.method, c.path, c.body, readonly); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s as readonly: %d, want 403 (%s)", c.method, c.path, w.Code, w.Body)
		}
		ev := rec.Last(t)
		if ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != route.ReasonPermissionDenied {
			t.Fatalf("%s %s: audited %s %+v", c.method, c.path, ev.Action, ev.Event.Details)
		}
	}
	got, _ := svc.GetKey(t.Context(), "t1", key.ID)
	if got.ExportAllowed {
		t.Fatal("readonly user made the key exportable")
	}
}

// key.access.manage lets a user change the grants of keys they created; an
// admin may change any key's. Anyone else is refused as not_key_owner.
func TestKeyGrantsChangeOnlyByCreatorOrAdmin(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key := ownedKey(t, svc) // created by owner-1
	body := `{"grants":[{"subject_type":"user","subject_id":"mallory","operations":["decrypt","export"]}]}`
	path := "/keys/" + key.ID + "/access-policy"

	manager := func(user string) *pkgauth.Claims {
		return &pkgauth.Claims{UserID: user, TenantID: "t1", Role: "operator", Permissions: []string{"key.access.manage"}}
	}
	if w := callKeycore(h, http.MethodPut, path, body, manager("mallory")); w.Code != http.StatusForbidden {
		t.Fatalf("non-owner granted themselves the key: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "access_policy_updated" || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != "not_key_owner" {
		t.Fatalf("refusal audited as %s %s %+v", ev.Action, ev.Event.Result, ev.Event.Details)
	}
	if grants, _ := svc.store.ListKeyAccessGrants(t.Context(), "t1", key.ID); len(grants) != 0 {
		t.Fatalf("refused change was stored: %+v", grants)
	}

	if w := callKeycore(h, http.MethodPut, path, body, manager("owner-1")); w.Code != http.StatusOK {
		t.Fatalf("creator refused: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Event.Result != route.ResultSuccess || ev.Event.ActorID != "owner-1" {
		t.Fatalf("success audited as %+v", ev.Event)
	}
	admin := &pkgauth.Claims{UserID: "root-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	if w := callKeycore(h, http.MethodPut, path, `{"grants":[]}`, admin); w.Code != http.StatusOK {
		t.Fatalf("admin refused: %d %s", w.Code, w.Body)
	}
}

// The actor is the verified token's. A body naming another updated_by or
// created_by is rejected, not silently trusted as it was before.
func TestAccessRoutesTakeActorFromTokenOnly(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	key := ownedKey(t, svc)
	admin := &pkgauth.Claims{UserID: "root-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	cases := []struct{ method, path, body string }{
		{http.MethodPut, "/keys/" + key.ID + "/access-policy", `{"grants":[],"updated_by":"someone-else"}`},
		{http.MethodPost, "/access/groups", `{"name":"g","created_by":"someone-else"}`},
	}
	for _, c := range cases {
		if w := callKeycore(h, c.method, c.path, c.body, admin); w.Code != http.StatusBadRequest {
			t.Fatalf("%s %s accepted a body actor: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
}

// POST /keys used to take tenant_id from the body without comparing it with
// the token, so a caller could create keys in another tenant.
func TestCreateKeyRefusesAnotherTenantInBody(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	caller := &pkgauth.Claims{UserID: "u1", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	req := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewBufferString(`{"tenant_id":"t2","name":"k","algorithm":"AES-256","key_type":"symmetric","purpose":"encrypt"}`))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), caller))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "create_requested" || ev.Event.Details["reason"] != route.ReasonTenantMismatch {
		t.Fatalf("audited as %s %+v", ev.Action, ev.Event.Details)
	}
}

// An interface's pqc_mode was stored but no listener read it, so it is gone
// (6.4.0-beta). A write that still sends it is rejected and audited, nothing
// is stored, and neither the response nor the event carries the field.
func TestInterfacePortPQCModeRemoved(t *testing.T) {
	h, svc, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	w := httptest.NewRecorder()
	serveAsAdmin(h, w, httptest.NewRequest(http.MethodPost, "/access/interface-ports?tenant_id=t1",
		bytes.NewBufferString(`{"interface_name":"kmip","port":5696,"protocol":"mtls","pqc_mode":"pqc_only"}`)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "pqc_mode") {
		t.Fatalf("pqc_mode write: %d %s, want 400 naming the field", w.Code, w.Body)
	}
	ev := rec.Last(t)
	if ev.Event.Result != route.ResultFailure || ev.Event.Details["error_code"] != "bad_request" || !strings.Contains(ev.Event.ErrorMessage, "pqc_mode") {
		t.Fatalf("rejected write audited as %s %s %+v %q", ev.Action, ev.Event.Result, ev.Event.Details, ev.Event.ErrorMessage)
	}
	ports, err := svc.ListKeyInterfacePorts(t.Context(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ports {
		if p.InterfaceName == "kmip" && p.UpdatedBy != "" {
			t.Fatalf("rejected write was stored: %+v", p)
		}
	}

	rec.Reset()
	w = httptest.NewRecorder()
	serveAsAdmin(h, w, httptest.NewRequest(http.MethodPost, "/access/interface-ports?tenant_id=t1",
		bytes.NewBufferString(`{"interface_name":"kmip","port":5696,"protocol":"mtls","enabled":true}`)))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "pqc_mode") {
		t.Fatalf("upsert: %d %s", w.Code, w.Body)
	}
	ev = rec.Last(t)
	if _, ok := ev.Event.Details["pqc_mode"]; ok || ev.Event.Result != route.ResultSuccess || ev.Event.Details["protocol"] != "mtls" {
		t.Fatalf("upsert audited as %s %+v", ev.Event.Result, ev.Event.Details)
	}
}

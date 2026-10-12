package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/tenantcheck"
)

// memStore holds what the request path writes. Any Store method it doesn't
// define is a nil call and fails the test: a refused request must not reach
// storage at all.
type memStore struct {
	Store
	settings map[string]AutokeySettings
	requests map[string]AutokeyRequest
}

func newMemStore() *memStore {
	return &memStore{settings: map[string]AutokeySettings{}, requests: map[string]AutokeyRequest{}}
}

func (m *memStore) GetSettings(_ context.Context, tenantID string) (AutokeySettings, error) {
	if s, ok := m.settings[tenantID]; ok {
		return s, nil
	}
	s := defaultSettings(tenantID)
	s.Enabled = true
	return s, nil
}

func (m *memStore) UpsertSettings(_ context.Context, item AutokeySettings) (AutokeySettings, error) {
	m.settings[item.TenantID] = item
	return item, nil
}

// Every binding already has a handle, so a request is recorded and answered
// without keycore or governance.
func (m *memStore) GetHandleByBinding(_ context.Context, tenantID, service, resourceType, resourceRef string) (AutokeyHandle, error) {
	return AutokeyHandle{ID: "akh-1", TenantID: tenantID, ServiceName: service, ResourceType: resourceType, ResourceRef: resourceRef, HandleName: "h", KeyID: "key-1"}, nil
}

func (m *memStore) CreateRequest(_ context.Context, item AutokeyRequest) error {
	m.requests[item.ID] = item
	return nil
}

func (m *memStore) GetRequest(_ context.Context, tenantID, id string) (AutokeyRequest, error) {
	item, ok := m.requests[id]
	if !ok || item.TenantID != tenantID {
		return AutokeyRequest{}, errNotFound
	}
	return item, nil
}

func autokeyCall(h http.Handler, method, target, body string, claims *pkgauth.Claims) (*httptest.ResponseRecorder, map[string]interface{}) {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	out := map[string]interface{}{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

// Every route refuses a caller without a token, without the permission, or
// naming another tenant, and audits the refusal.
func TestRoutesRefuseAndAudit(t *testing.T) {
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, NewHandler(NewService(newMemStore(), nil, nil, nil), rec, nil).router, rec)
}

// Until 13.0.0-beta the handlers took the tenant from the request and never
// compared it with the token: a signed-in caller of one tenant read and
// changed another tenant's settings, templates, policies and key requests.
func TestAnotherTenantIsRefusedHoweverItIsNamed(t *testing.T) {
	store := newMemStore()
	rec := &routetest.Recorder{}
	h := NewHandler(NewService(store, nil, nil, nil), rec, nil)
	admin := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "tenant-admin", Permissions: []string{"*"}}

	for _, tc := range []struct{ name, method, target, body string }{
		{"query", http.MethodGet, "/autokey/settings?tenant_id=t2", ""},
		{"query, write", http.MethodPut, "/autokey/settings?tenant_id=t2", `{"enabled":false}`},
		{"body", http.MethodPut, "/autokey/settings", `{"tenant_id":"t2","enabled":false}`},
		{"body, request", http.MethodPost, "/autokey/requests", `{"tenant_id":"t2","service_name":"db","resource_type":"table","resource_ref":"orders"}`},
	} {
		rec.Reset()
		w, _ := autokeyCall(h, tc.method, tc.target, tc.body, admin)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: want 403, got %d %s", tc.name, w.Code, w.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "tenant_mismatch" {
			t.Fatalf("%s: the refusal is audited with its reason: %+v", tc.name, ev)
		}
	}
	// Naming one tenant in the query and another in the body is refused
	// rather than resolved.
	if w, _ := autokeyCall(h, http.MethodPut, "/autokey/settings?tenant_id=t1", `{"tenant_id":"t2"}`, admin); w.Code < 400 {
		t.Fatalf("two tenants in one request: got %d", w.Code)
	}
	if len(store.settings) != 0 || len(store.requests) != 0 {
		t.Fatalf("a refused request reached storage: %v %v", store.settings, store.requests)
	}

	// The caller's own tenant, named or not, answers.
	for _, target := range []string{"/autokey/settings", "/autokey/settings?tenant_id=t1"} {
		if w, _ := autokeyCall(h, http.MethodGet, target, "", admin); w.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d %s", target, w.Code, w.Body)
		}
	}
	// A token is required, and reading is not asking: each needs its permission.
	if w, _ := autokeyCall(h, http.MethodGet, "/autokey/settings?tenant_id=t1", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", w.Code)
	}
	reader := &pkgauth.Claims{UserID: "bob", TenantID: "t1", Role: "readonly", Permissions: []string{"autokey.read"}}
	if w, _ := autokeyCall(h, http.MethodGet, "/autokey/settings", "", reader); w.Code != http.StatusOK {
		t.Fatalf("autokey.read reads: got %d", w.Code)
	}
	for _, tc := range []struct{ method, target, body string }{
		{http.MethodPut, "/autokey/settings", `{"enabled":false}`},
		{http.MethodPost, "/autokey/requests", `{"service_name":"db","resource_type":"table","resource_ref":"orders"}`},
	} {
		if w, _ := autokeyCall(h, tc.method, tc.target, tc.body, reader); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s with autokey.read only: want 403, got %d", tc.method, tc.target, w.Code)
		}
	}
}

// The requester of a key request, and who changed a setting, is the verified
// caller. The requester goes to governance, which keeps the requester from
// approving their own request, and becomes the key's creator.
func TestRequesterAndEditorAreTheVerifiedCaller(t *testing.T) {
	store := newMemStore()
	h := NewHandler(NewService(store, nil, nil, nil), nil, nil)
	alice := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "tenant-admin", Permissions: []string{"*"}}
	ask := `{"service_name":"db","resource_type":"table","resource_ref":"orders","justification":"new table","requester_id":"bob","requester_email":"bob@example.com","requester_ip":"10.0.0.1"}`

	w, out := autokeyCall(h, http.MethodPost, "/autokey/requests", ask, alice)
	if w.Code != http.StatusCreated {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	got, _ := out["request"].(map[string]interface{})
	if got["requester_id"] != "alice" || got["requester_email"] != nil || got["requester_ip"] != "198.51.100.7" {
		t.Fatalf("a person's request names the person and the address the edge saw: %v", got)
	}

	// A platform service acting for somebody says who.
	playbook := &pkgauth.Claims{ClientID: "kms-compliance", TenantID: tenantcheck.InternalServiceTenant(), Role: "client-service", Permissions: []string{"service.internal"}}
	w, out = autokeyCall(h, http.MethodPost, "/autokey/requests?tenant_id=t1", ask, playbook)
	if w.Code != http.StatusCreated {
		t.Fatalf("service request: %d %s", w.Code, w.Body)
	}
	if got, _ := out["request"].(map[string]interface{}); got["requester_id"] != "bob" || got["requester_email"] != "bob@example.com" || got["requester_ip"] != "10.0.0.1" {
		t.Fatalf("a platform service states the person it acts for: %v", got)
	}

	if w, _ := autokeyCall(h, http.MethodPut, "/autokey/settings", `{"enabled":true,"updated_by":"bob"}`, alice); w.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", w.Code, w.Body)
	}
	if by := store.settings["t1"].UpdatedBy; by != "alice" {
		t.Fatalf("updated_by is the caller, got %q", by)
	}
}

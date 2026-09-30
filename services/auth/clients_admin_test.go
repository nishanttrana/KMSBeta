package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

type clientAdminHarness struct {
	h     *Handler
	store *SQLStore
	pub   *mockPublisher
	rec   *routetest.Recorder
	admin string
}

func newClientAdminHarness(t *testing.T) *clientAdminHarness {
	t.Helper()
	h, logic, store, pub := newTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	admin, _, err := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "u-admin", false)
	if err != nil {
		t.Fatal(err)
	}
	return &clientAdminHarness{h: h, store: store, pub: pub, rec: rec, admin: admin}
}

func (c *clientAdminHarness) do(t *testing.T, method, path string, header map[string]string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	return w
}

func (c *clientAdminHarness) asAdmin(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return c.do(t, method, path, map[string]string{"Authorization": "Bearer " + c.admin, "X-Tenant-ID": "t1"}, body)
}

// registerAndActivate registers a REST client and approves it, returning its
// ID and the API key activation hands out once.
func (c *clientAdminHarness) registerAndActivate(t *testing.T) (string, string) {
	t.Helper()
	w := c.do(t, http.MethodPost, "/auth/register", nil, `{"tenant_id":"t1","client_name":"release-pipeline","interface_name":"rest"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	var reg struct{ RegistrationID string `json:"registration_id"` }
	_ = json.Unmarshal(w.Body.Bytes(), &reg)
	w = c.asAdmin(t, http.MethodPost, "/auth/register/"+reg.RegistrationID+"/activate", `{"tenant_id":"t1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("activate: %d %s", w.Code, w.Body.String())
	}
	var out struct{ APIKey string `json:"api_key"` }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return reg.RegistrationID, out.APIKey
}

func (c *clientAdminHarness) clientToken(t *testing.T, clientID, apiKey string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"tenant_id": "t1", "client_id": clientID})
	req := httptest.NewRequest(http.MethodPost, "/auth/client-token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	return w.Code
}

func TestClientAdminRefusalsAudited(t *testing.T) {
	c := newClientAdminHarness(t)
	routetest.RefusalsAudited(t, c.h.clientAdminRouter(), c.rec)
}

// Rotation must hand out a key that works and stop the old one at once.
// Before 7.16.0-beta it only rewrote the registration's prefix: the new key
// was never accepted and the old one kept working.
func TestRotatedClientKeyWorksAndOldKeyStops(t *testing.T) {
	c := newClientAdminHarness(t)
	id, oldKey := c.registerAndActivate(t)
	if code := c.clientToken(t, id, oldKey); code != http.StatusOK {
		t.Fatalf("activated key refused: %d", code)
	}
	w := c.asAdmin(t, http.MethodPost, "/auth/clients/"+id+"/rotate-key", `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if ev := c.rec.Last(t); ev.Action != "client_key_rotated" || ev.Event.Result != route.ResultSuccess || ev.Event.TargetID != id {
		t.Fatalf("rotation audit: %+v", ev)
	}
	var out struct{ APIKey string `json:"api_key"` }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if code := c.clientToken(t, id, out.APIKey); code != http.StatusOK {
		t.Fatalf("rotated key refused: %d", code)
	}
	if code := c.clientToken(t, id, oldKey); code != http.StatusUnauthorized {
		t.Fatalf("old key still accepted after rotation: %d", code)
	}
}

func TestRevokedClientKeyStops(t *testing.T) {
	c := newClientAdminHarness(t)
	id, key := c.registerAndActivate(t)
	if w := c.asAdmin(t, http.MethodPost, "/auth/clients/"+id+"/revoke", `{}`); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if ev := c.rec.Last(t); ev.Action != "client_revoked" || ev.Event.Result != route.ResultSuccess {
		t.Fatalf("revoke audit: %+v", ev)
	}
	if code := c.clientToken(t, id, key); code != http.StatusUnauthorized {
		t.Fatalf("revoked client's key still accepted: %d", code)
	}
	// A revoked client has no key to rotate.
	if w := c.asAdmin(t, http.MethodPost, "/auth/clients/"+id+"/rotate-key", `{}`); w.Code != http.StatusConflict {
		t.Fatalf("rotate revoked: %d", w.Code)
	}
	wantAuthRefusal(t, c.rec.Last(t), "client_key_rotated", reasonClientState)
}

func TestPendingClientKeyRotationRefused(t *testing.T) {
	c := newClientAdminHarness(t)
	w := c.do(t, http.MethodPost, "/auth/register", nil, `{"tenant_id":"t1","client_name":"pending-one"}`)
	var reg struct{ RegistrationID string `json:"registration_id"` }
	_ = json.Unmarshal(w.Body.Bytes(), &reg)
	if w := c.asAdmin(t, http.MethodPost, "/auth/clients/"+reg.RegistrationID+"/rotate-key", `{}`); w.Code != http.StatusConflict {
		t.Fatalf("rotate pending: %d %s", w.Code, w.Body.String())
	}
	wantAuthRefusal(t, c.rec.Last(t), "client_key_rotated", reasonClientState)
}

// Activating a client that is no longer pending is refused and audited;
// it must not mint a second key.
func TestActivationOfApprovedClientRefusedAndAudited(t *testing.T) {
	c := newClientAdminHarness(t)
	id, _ := c.registerAndActivate(t)
	c.pub.subjects = nil
	w := c.asAdmin(t, http.MethodPost, "/auth/register/"+id+"/activate", `{"tenant_id":"t1"}`)
	if w.Code != http.StatusConflict || strings.Contains(w.Body.String(), "api_key\"") {
		t.Fatalf("re-activation: %d %s", w.Code, w.Body.String())
	}
	if !containsSubject(c.pub.subjects, "audit.auth.client_activation_refused") {
		t.Fatalf("refusal not audited: %v", c.pub.subjects)
	}
}

// Platform service identities are re-derived from the bootstrap secret;
// revoking or rotating them here would only lock the service out.
func TestServiceIdentityClientProtected(t *testing.T) {
	c := newClientAdminHarness(t)
	ctx := context.Background()
	if err := c.store.CreateClientRegistration(ctx, ClientRegistration{ID: "kms-cloud", TenantID: "t1", ClientName: "kms-cloud", ClientType: "service", InterfaceName: "rest", Status: "approved", AuthMode: "api_key"}); err != nil {
		t.Fatal(err)
	}
	if err := c.store.CreateAPIKey(ctx, APIKey{ID: "ak-svc", TenantID: "t1", ClientID: "kms-cloud", KeyHash: []byte("svc"), Name: "svc", Permissions: []string{"service.internal"}}); err != nil {
		t.Fatal(err)
	}
	for path, action := range map[string]string{
		"/auth/clients/kms-cloud/revoke":     "client_revoked",
		"/auth/clients/kms-cloud/rotate-key": "client_key_rotated",
	} {
		if w := c.asAdmin(t, http.MethodPost, path, `{}`); w.Code != http.StatusConflict {
			t.Fatalf("%s: %d", path, w.Code)
		}
		wantAuthRefusal(t, c.rec.Last(t), action, reasonServiceIdentityTarget)
	}
	if w := c.asAdmin(t, http.MethodDelete, "/auth/api-keys/ak-svc", ``); w.Code != http.StatusConflict {
		t.Fatalf("delete service key: %d", w.Code)
	}
	wantAuthRefusal(t, c.rec.Last(t), "api_key_revoked", reasonServiceIdentityTarget)
	if _, err := c.store.GetAPIKeyByID(ctx, "t1", "ak-svc"); err != nil {
		t.Fatalf("service key deleted: %v", err)
	}
}

// POST /auth/api-keys minted keys with any permissions the caller named.
// It is gone, and keys it left behind are retired at startup.
func TestUnboundAPIKeysRemovedAndRetired(t *testing.T) {
	c := newClientAdminHarness(t)
	if w := c.asAdmin(t, http.MethodPost, "/auth/api-keys", `{"name":"x","permissions":["*"]}`); w.Code == http.StatusCreated || w.Code == http.StatusOK {
		t.Fatalf("POST /auth/api-keys still served: %d", w.Code)
	}
	ctx := context.Background()
	id, _ := c.registerAndActivate(t)
	if err := c.store.CreateAPIKey(ctx, APIKey{ID: "ak-old", TenantID: "t1", UserID: "u-admin", KeyHash: []byte("old"), Name: "manual", Permissions: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	c.pub.subjects = nil
	retireUnboundAPIKeys(ctx, c.store, log.New(&bytes.Buffer{}, "", 0), c.pub)
	if _, err := c.store.GetAPIKeyByID(ctx, "t1", "ak-old"); err == nil {
		t.Fatal("unbound key survived retirement")
	}
	if !containsSubject(c.pub.subjects, "audit.auth.unbound_api_keys_retired") {
		t.Fatalf("retirement not audited: %v", c.pub.subjects)
	}
	if reg, err := c.store.GetClientRegistration(ctx, "t1", id); err != nil || reg.Status != "approved" {
		t.Fatalf("client-bound key touched: %v %v", reg.Status, err)
	}
	var bound int
	if err := c.store.db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_api_keys WHERE tenant_id='t1' AND client_id=$1`, id).Scan(&bound); err != nil || bound != 1 {
		t.Fatalf("client key count=%d err=%v", bound, err)
	}
	// Idempotent: nothing left, nothing emitted.
	c.pub.subjects = nil
	retireUnboundAPIKeys(ctx, c.store, log.New(&bytes.Buffer{}, "", 0), c.pub)
	if len(c.pub.subjects) != 0 {
		t.Fatalf("second run emitted %v", c.pub.subjects)
	}
}

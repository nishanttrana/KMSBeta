package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

type delegatedHarness struct {
	h     *Handler
	logic *AuthLogic
	store *SQLStore
	rec   *routetest.Recorder
}

func newDelegatedHarness(t *testing.T) *delegatedHarness {
	t.Helper()
	h, logic, store, _ := newTestHandler(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := context.Background()
	for _, r := range []TenantRole{
		{TenantID: "t1", RoleName: "ops", Permissions: []string{"auth.user.write", "auth.api_key.write", "auth.client.write"}},
		{TenantID: "t1", RoleName: "readonly", Permissions: []string{"auth.self.read"}},
	} {
		if err := store.CreateTenantRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []User{
		{ID: "u-admin", TenantID: "t1", Username: "admin", Email: "admin@example.com", Role: "tenant-admin", Status: "active"},
		{ID: "u-ops", TenantID: "t1", Username: "ops", Email: "ops@example.com", Role: "ops", Status: "active"},
		{ID: "u-viewer", TenantID: "t1", Username: "viewer", Email: "viewer@example.com", Role: "readonly", Status: "active"},
		{ID: "u-gone", TenantID: "t1", Username: "gone", Email: "gone@example.com", Role: "ops", Status: "inactive"},
		{ID: "u-target", TenantID: "t1", Username: "target", Email: "target@example.com", Role: "readonly", Status: "active"},
	} {
		u.Password = []byte("x")
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	return &delegatedHarness{h: h, logic: logic, store: store, rec: rec}
}

func (d *delegatedHarness) token(t *testing.T, clientID string) string {
	t.Helper()
	tok, _, err := d.logic.IssueClientJWT("root", clientID, "", "rest", []string{"service.internal"}, time.Minute, "api_key", nil, false, "")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (d *delegatedHarness) call(t *testing.T, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("X-Tenant-ID", "t1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	d.h.ServeHTTP(w, req)
	return w
}

func (d *delegatedHarness) last(t *testing.T) routetest.Recorded { return d.rec.Last(t) }

func wantAuthRefusal(t *testing.T, ev routetest.Recorded, action, reason string) {
	t.Helper()
	if ev.Action != action || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != reason {
		t.Fatalf("%s: result=%s reason=%v, want %s refused %s", ev.Action, ev.Event.Result, ev.Event.Details["reason"], action, reason)
	}
}

func delegate(onBehalfOf string) map[string]string {
	return map[string]string{"on_behalf_of": onBehalfOf, "reason": "playbook pb1 run pbrun_1", "playbook_run_id": "pbrun_1"}
}

// Every delegated route refuses anonymous and cross-tenant callers.
func TestDelegatedRoutesRefusalsAudited(t *testing.T) {
	d := newDelegatedHarness(t)
	routetest.RefusalsAudited(t, d.h.delegatedRouter(), d.rec)
}

// Only the compliance service identity may act on a person's behalf: not a
// user (even an administrator), not another platform service.
func TestDelegationOnlyForComplianceService(t *testing.T) {
	d := newDelegatedHarness(t)
	admin, _, _ := d.logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "u-admin", false)
	for _, tok := range []string{admin, d.token(t, "kms-keycore")} {
		if w := d.call(t, "/auth/delegated/users/u-target/disable", tok, delegate("u-admin")); w.Code != http.StatusForbidden {
			t.Fatalf("non-compliance caller: %d %s", w.Code, w.Body.String())
		}
		wantAuthRefusal(t, d.last(t), "delegated_user_disabled", reasonServiceIdentityRequired)
	}
	if u, _ := d.store.GetUserByID(context.Background(), "t1", "u-target"); u.Status != "active" {
		t.Fatal("refused caller changed the user")
	}
}

// The delegating person is checked now: unknown, inactive or lacking the
// permission, nothing happens.
func TestDelegationChecksTheDelegatorNow(t *testing.T) {
	d := newDelegatedHarness(t)
	tok := d.token(t, delegatingService)
	for who, reason := range map[string]string{"u-nobody": reasonDelegatorUnknown, "u-gone": reasonDelegatorInactive, "u-viewer": reasonDelegatorLacks} {
		if w := d.call(t, "/auth/delegated/users/u-target/disable", tok, delegate(who)); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", who, w.Code)
		}
		wantAuthRefusal(t, d.last(t), "delegated_user_disabled", reason)
	}
	if u, _ := d.store.GetUserByID(context.Background(), "t1", "u-target"); u.Status != "active" {
		t.Fatal("refused delegation changed the user")
	}

	w := d.call(t, "/auth/delegated/authority", tok, map[string]any{"user_id": "u-ops", "permissions": []string{"auth.user.write", "key.rotate"}})
	var out struct {
		Active  bool     `json:"active"`
		Missing []string `json:"missing"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusOK || !out.Active || len(out.Missing) != 1 || out.Missing[0] != "key.rotate" {
		t.Fatalf("authority: %d %s", w.Code, w.Body.String())
	}
	if ev := d.last(t); ev.Action != "delegated_authority_checked" || ev.Event.Result != route.ResultSuccess {
		t.Fatalf("authority event: %+v", ev)
	}
	w = d.call(t, "/auth/delegated/authority", tok, map[string]any{"user_id": "u-gone", "permissions": []string{"auth.user.write"}})
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Active {
		t.Fatal("inactive user reported active")
	}
}

// Disabling a user: done for a delegator who holds auth.user.write; never
// the delegator themself or the last administrator.
func TestDelegatedDisableUser(t *testing.T) {
	d := newDelegatedHarness(t)
	tok := d.token(t, delegatingService)
	ctx := context.Background()
	if w := d.call(t, "/auth/delegated/users/u-ops/disable", tok, delegate("u-ops")); w.Code != http.StatusConflict {
		t.Fatalf("self: %d", w.Code)
	}
	wantAuthRefusal(t, d.last(t), "delegated_user_disabled", reasonSelfTarget)
	if w := d.call(t, "/auth/delegated/users/u-admin/disable", tok, delegate("u-ops")); w.Code != http.StatusConflict {
		t.Fatalf("last admin: %d", w.Code)
	}
	wantAuthRefusal(t, d.last(t), "delegated_user_disabled", reasonLastAdministrator)

	if w := d.call(t, "/auth/delegated/users/u-target/disable", tok, delegate("u-ops")); w.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", w.Code, w.Body.String())
	}
	if u, _ := d.store.GetUserByID(ctx, "t1", "u-target"); u.Status == "active" {
		t.Fatal("user still active")
	}
	ev := d.last(t)
	if ev.Action != "delegated_user_disabled" || ev.Event.Result != route.ResultSuccess || ev.Event.Details["on_behalf_of"] != "u-ops" || ev.Event.Details["via"] != delegatingService || ev.Event.Details["playbook_run_id"] != "pbrun_1" || ev.Event.TargetID != "u-target" {
		t.Fatalf("disable event: %+v", ev.Event)
	}
}

// Revoking API keys and clients: done for user keys and clients; platform
// service identities are protected.
func TestDelegatedRevokeKeysAndClients(t *testing.T) {
	d := newDelegatedHarness(t)
	tok := d.token(t, delegatingService)
	ctx := context.Background()
	for _, k := range []APIKey{
		{ID: "ak-user", TenantID: "t1", UserID: "u-target", KeyHash: []byte("h1"), Name: "user key", Permissions: []string{"kms.read"}},
		{ID: "ak-svc", TenantID: "t1", ClientID: "kms-keycore", KeyHash: []byte("h2"), Name: "service", Permissions: []string{"service.internal"}},
	} {
		if err := d.store.CreateAPIKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if w := d.call(t, "/auth/delegated/api-keys/ak-svc/revoke", tok, delegate("u-ops")); w.Code != http.StatusConflict {
		t.Fatalf("service key: %d", w.Code)
	}
	wantAuthRefusal(t, d.last(t), "delegated_api_key_revoked", reasonServiceIdentityTarget)
	if w := d.call(t, "/auth/delegated/api-keys/ak-user/revoke", tok, delegate("u-ops")); w.Code != http.StatusOK {
		t.Fatalf("revoke key: %d %s", w.Code, w.Body.String())
	}
	if _, err := d.store.GetAPIKeyByID(ctx, "t1", "ak-user"); err == nil {
		t.Fatal("key still exists")
	}
	if w := d.call(t, "/auth/delegated/api-keys/ak-user/revoke", tok, delegate("u-ops")); w.Code != http.StatusNotFound {
		t.Fatalf("revoke twice: %d", w.Code)
	}

	for _, reg := range []ClientRegistration{
		{ID: "cl-app", TenantID: "t1", ClientName: "app", ClientType: "service", InterfaceName: "rest", Status: "approved", AuthMode: "api_key"},
		{ID: "kms-cloud", TenantID: "t1", ClientName: "kms-cloud", ClientType: "service", InterfaceName: "rest", Status: "approved", AuthMode: "api_key"},
	} {
		if err := d.store.CreateClientRegistration(ctx, reg); err != nil {
			t.Fatal(err)
		}
	}
	if w := d.call(t, "/auth/delegated/clients/kms-cloud/revoke", tok, delegate("u-ops")); w.Code != http.StatusConflict {
		t.Fatalf("service client: %d", w.Code)
	}
	wantAuthRefusal(t, d.last(t), "delegated_client_revoked", reasonServiceIdentityTarget)
	if w := d.call(t, "/auth/delegated/clients/cl-app/revoke", tok, delegate("u-ops")); w.Code != http.StatusOK {
		t.Fatalf("revoke client: %d %s", w.Code, w.Body.String())
	}
	if reg, _ := d.store.GetClientRegistration(ctx, "t1", "cl-app"); reg.Status != "revoked" {
		t.Fatalf("client status %s", reg.Status)
	}
	if ev := d.last(t); ev.Action != "delegated_client_revoked" || ev.Event.Result != route.ResultSuccess {
		t.Fatalf("client event: %+v", ev)
	}
}

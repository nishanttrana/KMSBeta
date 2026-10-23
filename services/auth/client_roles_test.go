package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// tokenPerms exchanges the client's API key for a token and returns the
// token's permissions, or the status of a refused exchange.
func (c *clientAdminHarness) tokenPerms(t *testing.T, clientID, apiKey string) ([]string, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"tenant_id": "t1", "client_id": clientID})
	req := httptest.NewRequest(http.MethodPost, "/auth/client-token", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return nil, w.Code
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	claims, err := c.logic.ParseJWT(out.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ClientID != clientID {
		t.Fatalf("token client_id %q", claims.ClientID)
	}
	return claims.Permissions, w.Code
}

// A client's tokens hold its granted role's permissions, as the role is when
// each is issued; without a role, the default client permissions; with a
// deleted role, nothing. Granting a role the administrator doesn't fully
// hold is refused and audited.
func TestClientRoleGrantsItsPermissions(t *testing.T) {
	c := newClientAdminHarness(t)
	ctx := context.Background()
	if err := c.store.CreateTenantRole(ctx, TenantRole{TenantID: "t1", RoleName: "key-operator", Permissions: []string{"key.encrypt", "key.decrypt"}}); err != nil {
		t.Fatal(err)
	}
	id, key := c.registerAndActivate(t)
	if perms, _ := c.tokenPerms(t, id, key); !slices.Contains(perms, "kms.read") || slices.Contains(perms, "key.encrypt") {
		t.Fatalf("default client permissions: %v", perms)
	}

	w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id+"/role", `{"role":"key-operator"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("set role: %d %s", w.Code, w.Body)
	}
	if ev := c.rec.Last(t); ev.Action != "client_role_set" || ev.Event.Details["role"] != "key-operator" {
		t.Fatalf("set role audited: %+v", ev)
	}
	perms, _ := c.tokenPerms(t, id, key)
	slices.Sort(perms)
	if strings.Join(perms, ",") != "key.decrypt,key.encrypt" {
		t.Fatalf("role permissions: %v", perms)
	}
	if ev := lastPublished(c.pub, "audit.auth.client_token_issued"); ev == nil || eventData(ev)["role"] != "key-operator" {
		t.Fatalf("token audit names the role: %+v", ev)
	}
	// The role as it is now.
	if err := c.store.UpdateTenantRole(ctx, TenantRole{TenantID: "t1", RoleName: "key-operator", Permissions: []string{"key.encrypt"}}); err != nil {
		t.Fatal(err)
	}
	if perms, _ := c.tokenPerms(t, id, key); strings.Join(perms, ",") != "key.encrypt" {
		t.Fatalf("an edited role: %v", perms)
	}
	// A deleted role leaves the client with nothing.
	if err := c.store.DeleteTenantRole(ctx, "t1", "key-operator"); err != nil {
		t.Fatal(err)
	}
	if _, code := c.tokenPerms(t, id, key); code != http.StatusForbidden {
		t.Fatalf("a deleted role: %d", code)
	}
	// Clearing restores the default.
	if w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id+"/role", `{"role":""}`); w.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", w.Code, w.Body)
	}
	if perms, _ := c.tokenPerms(t, id, key); !slices.Contains(perms, "kms.write") {
		t.Fatalf("cleared: %v", perms)
	}
	if w := c.asAdmin(t, http.MethodGet, "/auth/clients/"+id+"/role", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"role":""`) {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}

	// An administrator can't grant more than they hold.
	if err := c.store.CreateTenantRole(ctx, TenantRole{TenantID: "t1", RoleName: "everything", Permissions: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	limited, _, err := c.logic.IssueJWT("t1", "operator", []string{"auth.client.write", "auth.client.read", "key.encrypt"}, "u-limited", false, "")
	if err != nil {
		t.Fatal(err)
	}
	w = c.do(t, http.MethodPut, "/auth/clients/"+id+"/role", map[string]string{"Authorization": "Bearer " + limited, "X-Tenant-ID": "t1"}, `{"role":"everything"}`)
	if w.Code != http.StatusForbidden {
		t.Fatalf("escalation: %d %s", w.Code, w.Body)
	}
	wantAuthRefusal(t, c.rec.Last(t), "client_role_set", reasonRoleExceedsCaller)
	if w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id+"/role", `{"role":"nope"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown role: %d", w.Code)
	}
	wantAuthRefusal(t, c.rec.Last(t), "client_role_set", "role_not_found")
}

// Whatever role a root-tenant client holds, it is never a platform
// administrator: that is a person's.
func TestClientIsNeverPlatformAdministrator(t *testing.T) {
	c := newClientAdminHarness(t)
	clientToken, _, err := c.logic.IssueClientJWT("root", "release-pipeline", "release-pipeline", "rest", []string{"*"}, 0, "api_key", nil, false, "")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := c.logic.ParseJWT(clientToken)
	if err != nil {
		t.Fatal(err)
	}
	if platformAdministrator(claims, "auth.tenant.write") {
		t.Fatal("a client token with * acted as a platform administrator")
	}
	person, _, _ := c.logic.IssueJWT("root", "admin", []string{"*"}, "root-admin", false, "")
	pc, _ := c.logic.ParseJWT(person)
	if !platformAdministrator(pc, "auth.tenant.write") {
		t.Fatal("the root administrator is no longer a platform administrator")
	}
}

// lastPublished is the last event published under subject, or nil.
func lastPublished(p *mockPublisher, subject string) map[string]any {
	for i := len(p.subjects) - 1; i >= 0; i-- {
		if p.subjects[i] == subject {
			var ev map[string]any
			_ = json.Unmarshal(p.payloads[i], &ev)
			return ev
		}
	}
	return nil
}

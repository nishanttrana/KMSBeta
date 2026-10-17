package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

// Tenant and user administration (Administration → Tenant Administration and
// User Management). Only an administrator of the platform (root) tenant acts
// on another tenant or on the tenant list; every role assigned is one the
// tenant defines; a policy edit lands on the tenant it names; a refused
// tenant create leaves nothing behind. Refusals are audited.

type tenantAdminHarness struct {
	h     *Handler
	logic *AuthLogic
	store *SQLStore
	pub   *payloadPublisher
}

func newTenantAdminHarness(t *testing.T) *tenantAdminHarness {
	t.Helper()
	h, logic, store, _ := newTestHandlerWithRoles(t)
	pub := &payloadPublisher{}
	h.events = pub
	ctx := context.Background()
	for _, tn := range []string{"root", "t2"} {
		if err := store.CreateTenant(ctx, Tenant{ID: tn, Name: tn, Status: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := h.ensureTenantDefaults(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []User{
		{ID: "u-root-admin", TenantID: "root", Username: "admin", Email: "admin@root.example", Role: "tenant-admin", Status: "active"},
		{ID: "u-t1-admin", TenantID: "t1", Username: "admin", Email: "admin@t1.example", Role: "admin", Status: "active"},
		{ID: "u-t1-bob", TenantID: "t1", Username: "bob", Email: "bob@t1.example", Role: "readonly", Status: "active"},
	} {
		u.Password = []byte("x")
		if err := store.CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	return &tenantAdminHarness{h: h, logic: logic, store: store, pub: pub}
}

func (a *tenantAdminHarness) token(t *testing.T, tenant, role, userID string, perms ...string) string {
	t.Helper()
	tok, _, err := a.logic.IssueJWT(tenant, role, perms, userID, false)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (a *tenantAdminHarness) do(t *testing.T, token, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	a.h.ServeHTTP(rr, req)
	return rr
}

func (a *tenantAdminHarness) rootAdmin(t *testing.T) string {
	return a.token(t, "root", "tenant-admin", "u-root-admin", "*")
}

func (a *tenantAdminHarness) t1Admin(t *testing.T) string {
	return a.token(t, "t1", "admin", "u-t1-admin", "*")
}

func (a *tenantAdminHarness) refused(t *testing.T, reason string) {
	t.Helper()
	ev, ok := a.pub.last("audit.auth.request_refused")
	if !ok || eventData(ev)["reason"] != reason || eventData(ev)["result"] != "refused" {
		t.Fatalf("the refusal must be audited with reason %s: %+v", reason, ev)
	}
}

// A tenant's own administrator holds "*" in that tenant, and before this
// change "*" or a role named super-admin opened every tenant: the tenant
// list, other tenants' users (a root admin's password reset included) and
// tenant deletion.
func TestOnlyAPlatformAdministratorActsAcrossTenants(t *testing.T) {
	a := newTenantAdminHarness(t)
	tenantAdmin := a.t1Admin(t)
	superNamed := a.token(t, "t1", "super-admin", "u-t1-admin", "auth.user.read")

	cases := []struct{ method, path, body string }{
		{http.MethodGet, "/tenants", ""},
		{http.MethodPost, "/tenants", `{"id":"t9","name":"t9"}`},
		{http.MethodPost, "/tenants/t2/disable", `{}`},
		{http.MethodGet, "/auth/users?tenant_id=root", ""},
		{http.MethodPost, "/auth/users/u-root-admin/reset-password?tenant_id=root", `{"new_password":"Taken-Over-2026!"}`},
		{http.MethodPut, "/auth/users/u-root-admin/status?tenant_id=root", `{"status":"inactive"}`},
		{http.MethodPut, "/auth/password-policy?tenant_id=root", `{"min_length":8}`},
	}
	for _, tc := range cases {
		rr := a.do(t, tenantAdmin, tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s by a tenant administrator: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
		a.refused(t, reasonNotPlatformAdmin)
		// A role named super-admin is a name, not a grant.
		if rr := a.do(t, superNamed, tc.method, tc.path, tc.body); rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s by a role named super-admin: %d %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
	}
	if u, _ := a.store.GetUserByID(context.Background(), "root", "u-root-admin"); u.Status != "active" {
		t.Fatal("a tenant administrator changed a root user")
	}

	root := a.rootAdmin(t)
	if rr := a.do(t, root, http.MethodGet, "/tenants", ""); rr.Code != http.StatusOK {
		t.Fatalf("root administrator lists tenants: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, root, http.MethodGet, "/auth/users?tenant_id=t1", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "bob") {
		t.Fatalf("root administrator lists t1 users: %d %s", rr.Code, rr.Body.String())
	}
	// A root user without tenant permissions stays in root.
	rootReader := a.token(t, "root", "readonly", "u-r", "auth.user.read")
	if rr := a.do(t, rootReader, http.MethodGet, "/auth/users?tenant_id=t1", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("root readonly user reads another tenant: %d", rr.Code)
	}
	// Inside its own tenant the tenant administrator keeps working.
	if rr := a.do(t, tenantAdmin, http.MethodGet, "/auth/users", ""); rr.Code != http.StatusOK {
		t.Fatalf("tenant administrator lists own users: %d %s", rr.Code, rr.Body.String())
	}
}

func TestLegacyRoutePermissionRefusalIsAudited(t *testing.T) {
	a := newTenantAdminHarness(t)
	reader := a.token(t, "t1", "readonly", "u-t1-bob", "auth.self.read")
	if rr := a.do(t, reader, http.MethodPost, "/auth/users", `{"username":"x","email":"x@x.io","password":"Abcdef-12345!","role":"readonly"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("missing permission: %d", rr.Code)
	}
	a.refused(t, "permission_denied")
	if rr := a.do(t, "not-a-token", http.MethodGet, "/auth/users", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rr.Code)
	}
	a.refused(t, "invalid_token")
}

// The console offered viewer, operator, approver and auditor, none of which
// a tenant defines: a user created as "viewer" could never sign in.
func TestEveryAssignedRoleIsDefinedByTheTenant(t *testing.T) {
	a := newTenantAdminHarness(t)
	tok := a.t1Admin(t)
	if rr := a.do(t, tok, http.MethodPost, "/auth/users", `{"username":"vic","email":"vic@t1.example","password":"Abcdef-12345!","role":"viewer"}`); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "unknown_role") {
		t.Fatalf("undefined role on create: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, tok, http.MethodPut, "/auth/users/u-t1-bob/role", `{"role":"operator"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("undefined role on update: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, tok, http.MethodPut, "/auth/groups/g1/role", `{"role_name":"auditor"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("undefined role on group binding: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, tok, http.MethodPut, "/auth/scim/settings", `{"default_role":"viewer"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("undefined SCIM default role: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, tok, http.MethodPost, "/auth/users", `{"username":"ann","email":"ann@t1.example","password":"Abcdef-12345!","role":"audit"}`); rr.Code != http.StatusCreated {
		t.Fatalf("defined role on create: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, tok, http.MethodPut, "/auth/users/u-t1-bob/role", `{"role":"backup"}`); rr.Code != http.StatusOK {
		t.Fatalf("defined role on update: %d %s", rr.Code, rr.Body.String())
	}
}

func TestRolesListedAreTheTenantsOwn(t *testing.T) {
	a := newTenantAdminHarness(t)
	rec := &routetest.Recorder{}
	a.h.kernelAudit = rec
	names := func(rr *httptest.ResponseRecorder) []string {
		var out struct {
			Items []TenantRole `json:"items"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		var n []string
		for _, r := range out.Items {
			n = append(n, r.RoleName)
		}
		return n
	}
	rr := a.do(t, a.t1Admin(t), http.MethodGet, "/auth/roles", "")
	if rr.Code != http.StatusOK || strings.Join(names(rr), ",") != "admin,audit,backup,cli-user,readonly,tenant-admin" {
		t.Fatalf("own roles: %d %v %s", rr.Code, names(rr), rr.Body.String())
	}
	if rr := a.do(t, a.t1Admin(t), http.MethodGet, "/auth/roles?tenant_id=root", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("another tenant's roles: %d", rr.Code)
	}
	if last := rec.Last(t); last.Action != "roles_listed" || last.Event.Result != "refused" || last.Event.Details["reason"] != reasonNotPlatformAdmin {
		t.Fatalf("the refusal must be audited: %+v", last)
	}
	if rr := a.do(t, a.rootAdmin(t), http.MethodGet, "/auth/roles?tenant_id=t1", ""); rr.Code != http.StatusOK || len(names(rr)) != 6 {
		t.Fatalf("root administrator reads t1 roles: %d %s", rr.Code, rr.Body.String())
	}
	routetest.RefusalsAudited(t, a.h.rolesRouter(), rec)
}

// An administrator who demotes or deactivates themselves locks the tenant
// out of its own administration.
func TestAdministratorCannotDemoteOrDeactivateThemselves(t *testing.T) {
	a := newTenantAdminHarness(t)
	tok := a.t1Admin(t)
	if rr := a.do(t, tok, http.MethodPut, "/auth/users/u-t1-admin/role", `{"role":"readonly"}`); rr.Code != http.StatusConflict {
		t.Fatalf("self demotion: %d %s", rr.Code, rr.Body.String())
	}
	a.refused(t, reasonSelfChange)
	if rr := a.do(t, tok, http.MethodPut, "/auth/users/u-t1-admin/status", `{"status":"inactive"}`); rr.Code != http.StatusConflict {
		t.Fatalf("self deactivation: %d %s", rr.Code, rr.Body.String())
	}
	a.refused(t, reasonSelfChange)
	if u, _ := a.store.GetUserByID(context.Background(), "t1", "u-t1-admin"); u.Role != "admin" || u.Status != "active" {
		t.Fatalf("the refused change was applied: %+v", u)
	}
	if rr := a.do(t, tok, http.MethodPut, "/auth/users/u-t1-bob/status", `{"status":"inactive"}`); rr.Code != http.StatusOK {
		t.Fatalf("deactivating another user: %d %s", rr.Code, rr.Body.String())
	}
}

// The tenant page's Security tab showed the chosen tenant but read and
// saved the caller's own policy.
func TestPolicyEditLandsOnTheTenantItNames(t *testing.T) {
	a := newTenantAdminHarness(t)
	root := a.rootAdmin(t)
	if rr := a.do(t, root, http.MethodPut, "/auth/password-policy?tenant_id=t2", `{"min_length":20}`); rr.Code != http.StatusOK {
		t.Fatalf("set t2 policy: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, root, http.MethodPut, "/auth/security-policy?tenant_id=t2", `{"max_failed_attempts":3}`); rr.Code != http.StatusOK {
		t.Fatalf("set t2 lockout: %d %s", rr.Code, rr.Body.String())
	}
	ctx := context.Background()
	if p, _ := a.h.resolvePasswordPolicy(ctx, "t2"); p.MinLength != 20 {
		t.Fatalf("t2 policy not changed: %+v", p)
	}
	if p, _ := a.h.resolvePasswordPolicy(ctx, "root"); p.MinLength == 20 {
		t.Fatal("the edit for t2 changed root's policy")
	}
	if p, _ := a.h.resolveSecurityPolicy(ctx, "t2"); p.MaxFailedAttempts != 3 {
		t.Fatalf("t2 lockout not changed: %+v", p)
	}
	rr := a.do(t, root, http.MethodGet, "/auth/password-policy?tenant_id=t2", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"min_length":20`) {
		t.Fatalf("read t2 policy: %d %s", rr.Code, rr.Body.String())
	}
}

// A create whose admin password failed the policy left the tenant behind
// without an administrator, and a corrected retry then failed on the ID.
func TestTenantCreateLeavesNothingBehindWhenRefused(t *testing.T) {
	a := newTenantAdminHarness(t)
	root := a.rootAdmin(t)
	ctx := context.Background()
	refusals := []struct{ body, code string }{
		{`{"id":"acme","name":"Acme","admin_username":"admin","admin_email":"a@acme.io","admin_password":"short"}`, "bad_request"},
		{`{"id":"acme","name":"Acme","admin_username":"owner","admin_email":"o@acme.io","admin_password":"Acme-Admin-2026!","admin_role":"viewer"}`, "bad_request"},
		{`{"id":"bad id!","name":"Acme"}`, "bad_request"},
		{`{"id":"acme","name":""}`, "bad_request"},
		{`{"id":"t2","name":"dup"}`, "tenant_exists"},
	}
	for _, tc := range refusals {
		rr := a.do(t, root, http.MethodPost, "/tenants", tc.body)
		if rr.Code < 400 || rr.Code >= 500 || !strings.Contains(rr.Body.String(), tc.code) {
			t.Fatalf("%s: %d %s", tc.body, rr.Code, rr.Body.String())
		}
	}
	if _, err := a.store.GetTenant(ctx, "acme"); err == nil {
		t.Fatal("a refused create left the tenant behind")
	}
	rr := a.do(t, root, http.MethodPost, "/tenants", `{"id":"acme","name":"Acme","admin_username":"owner","admin_email":"o@acme.io","admin_password":"Acme-Admin-2026!"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("corrected create: %d %s", rr.Code, rr.Body.String())
	}
	users, _ := a.store.ListUsers(ctx, "acme")
	if len(users) != 1 || users[0].Role != "tenant-admin" || !users[0].MustChangePassword {
		t.Fatalf("acme administrator: %+v", users)
	}
	if _, err := a.store.GetRolePermissions(ctx, "acme", "readonly"); err != nil {
		t.Fatalf("acme default roles: %v", err)
	}
	if _, ok := a.pub.last("audit.auth.tenant_created"); !ok {
		t.Fatal("tenant_created not audited")
	}
}

// Re-enabling a tenant sends only its status and blanked the name.
func TestTenantUpdateChangesOnlyWhatItNames(t *testing.T) {
	a := newTenantAdminHarness(t)
	root := a.rootAdmin(t)
	if rr := a.do(t, root, http.MethodPut, "/tenants/t2", `{"name":"Second"}`); rr.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rr.Code, rr.Body.String())
	}
	if rr := a.do(t, root, http.MethodPut, "/tenants/t2", `{"status":"active"}`); rr.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rr.Code, rr.Body.String())
	}
	if tn, _ := a.store.GetTenant(context.Background(), "t2"); tn.Name != "Second" || tn.Status != "active" {
		t.Fatalf("tenant after updates: %+v", tn)
	}
	if rr := a.do(t, root, http.MethodPut, "/tenants/t2", `{"status":"suspended"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown status: %d", rr.Code)
	}
}

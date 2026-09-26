package route_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func claims(tenant string, perms ...string) *pkgauth.Claims {
	return &pkgauth.Claims{UserID: "u1", TenantID: tenant, Role: "operator", Permissions: perms}
}

func serve(t *testing.T, r *route.Router, method, target, body string, c *pkgauth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if c != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), c))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func newRouter() (*route.Router, *routetest.Recorder, *string) {
	rec := &routetest.Recorder{}
	r := route.New("demo", rec, nil)
	var seenTenant string
	r.Handle("POST /things", route.Spec{Action: "thing.created", Permission: "demo.write", Resource: "thing"}, func(c *route.Call) {
		var req struct {
			TenantID string `json:"tenant_id"`
			Name     string `json:"name"`
		}
		if !c.Decode(&req) {
			return
		}
		seenTenant = c.Tenant
		c.Target("th_1")
		c.Detail("name", req.Name)
		c.JSON(http.StatusCreated, map[string]interface{}{"id": "th_1"})
	})
	r.Handle("GET /things/{id}", route.Spec{Action: "thing.read", Permission: "demo.read", Resource: "thing", TargetParam: "id"}, func(c *route.Call) {
		seenTenant = c.Tenant
		if c.R.PathValue("id") == "missing" {
			c.Error(http.StatusNotFound, "not_found", "no such thing")
			return
		}
		if c.R.PathValue("id") == "preview" {
			c.Refuse(http.StatusConflict, "feature_preview", "preview only")
			return
		}
		c.JSON(http.StatusOK, nil)
	})
	r.Handle("GET /health", route.Spec{Action: "health", Permission: route.Authenticated, Tenancy: route.PlatformScoped}, func(c *route.Call) {
		c.JSON(http.StatusOK, nil)
	})
	return r, rec, &seenTenant
}

func TestEveryRouteRefusesAndAudits(t *testing.T) {
	r, rec, _ := newRouter()
	routetest.RefusalsAudited(t, r, rec)
}

func TestSuccessEventCarriesActorTenantTarget(t *testing.T) {
	r, rec, seen := newRouter()
	w := serve(t, r, "POST", "/things", `{"tenant_id":"t1","name":"a"}`, claims("t1", "demo.write"))
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if *seen != "t1" {
		t.Fatalf("handler tenant %q", *seen)
	}
	ev := rec.Last(t)
	e := ev.Event
	if ev.Action != "thing.created" || e.Result != "success" || e.TenantID != "t1" || e.ActorID != "u1" ||
		e.ActorType != "user" || e.TargetType != "thing" || e.TargetID != "th_1" || e.CorrelationID == "" ||
		e.Details["name"] != "a" || e.Details["severity"] != "info" {
		t.Fatalf("unexpected event %+v", ev)
	}
}

func TestBodyTenantCannotCrossTenants(t *testing.T) {
	r, rec, seen := newRouter()
	*seen = ""
	w := serve(t, r, "POST", "/things", `{"tenant_id":"victim","name":"a"}`, claims("t1", "demo.write"))
	if w.Code != http.StatusForbidden || *seen != "" {
		t.Fatalf("cross-tenant body accepted: %d handler-tenant=%q", w.Code, *seen)
	}
	e := rec.Last(t).Event
	if e.Result != "refused" || e.Details["reason"] != route.ReasonTenantMismatch ||
		e.TenantID != "t1" || e.Details["requested_tenant"] != "victim" {
		t.Fatalf("event %+v", e)
	}
}

func TestConflictingTenantSourcesRefused(t *testing.T) {
	r, rec, _ := newRouter()
	// A root token (no tenant) is allowed any tenant, but not two at once.
	w := serve(t, r, "POST", "/things?tenant_id=a", `{"tenant_id":"b","name":"x"}`, claims("", "*"))
	if w.Code != http.StatusForbidden || rec.Last(t).Event.Details["reason"] != route.ReasonTenantConflict {
		t.Fatalf("conflict not refused: %d %+v", w.Code, rec.Last(t).Event)
	}
}

func TestTokenTenantIsTheDefault(t *testing.T) {
	r, _, seen := newRouter()
	if w := serve(t, r, "GET", "/things/x", "", claims("t1", "demo.read")); w.Code != http.StatusOK || *seen != "t1" {
		t.Fatalf("status %d tenant %q", w.Code, *seen)
	}
	if w := serve(t, r, "GET", "/things/x", "", claims("", "*")); w.Code != http.StatusBadRequest {
		t.Fatalf("root token without a tenant: status %d, want 400", w.Code)
	}
}

func TestServicePrincipalActsForRequestTenant(t *testing.T) {
	t.Setenv("INTERNAL_SERVICE_TENANT", "root")
	r, rec, seen := newRouter()
	svc := &pkgauth.Claims{ClientID: "kms-audit", TenantID: "root", Role: "client-service", Permissions: []string{"service.internal"}}
	if w := serve(t, r, "GET", "/things/x?tenant_id=t9", "", svc); w.Code != http.StatusOK || *seen != "t9" {
		t.Fatalf("status %d tenant %q", w.Code, *seen)
	}
	if rec.Last(t).Event.ActorType != "service" {
		t.Fatalf("actor type %q", rec.Last(t).Event.ActorType)
	}
	// A look-alike without the reserved permission is an ordinary client.
	fake := &pkgauth.Claims{ClientID: "kms-audit", TenantID: "root", Role: "client-service", Permissions: []string{"demo.read"}}
	if w := serve(t, r, "GET", "/things/x?tenant_id=t9", "", fake); w.Code != http.StatusForbidden {
		t.Fatalf("look-alike service crossed tenants: %d", w.Code)
	}
}

func TestFailureAndHandlerRefusalAreAudited(t *testing.T) {
	r, rec, _ := newRouter()
	serve(t, r, "GET", "/things/missing", "", claims("t1", "demo.read"))
	if e := rec.Last(t).Event; e.Result != "failure" || e.StatusCode != 404 || e.Details["error_code"] != "not_found" || e.TargetID != "missing" {
		t.Fatalf("failure event %+v", e)
	}
	serve(t, r, "GET", "/things/preview", "", claims("t1", "demo.read"))
	if e := rec.Last(t).Event; e.Result != "refused" || e.Details["reason"] != "feature_preview" || e.Details["severity"] != "warning" {
		t.Fatalf("refusal event %+v", e)
	}
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		grant, perm string
		want        bool
	}{
		{"*", "secrets.delete", true},
		{"secrets.read", "secrets.read", true},
		{"secrets.read", "secrets.write", false},
		{"secrets.*", "secrets.value.read", true},
		{"secrets.*", "secretsx.read", false},
		{"kms.read", "secrets.value.read", true},
		{"kms.read", "secrets.write", false},
		{"kms.write", "secrets.delete", true},
		{"kms.write", "secrets.read", false},
		{"kms.write", "auth.user.write", false}, // coarse grants never reach admin domains
		{"kms.read", "cluster.read", false},
		{"service.internal", "secrets.read", false}, // only a real service principal
	}
	for _, c := range cases {
		if got := route.Allowed(claims("t1", c.grant), c.perm); got != c.want {
			t.Errorf("grant %q perm %q: got %v", c.grant, c.perm, got)
		}
	}
	if route.Allowed(nil, route.Authenticated) {
		t.Error("nil claims allowed")
	}
}

func TestInvalidSpecsFailAtRegistration(t *testing.T) {
	bad := map[string]route.Spec{
		"no action":        {Permission: "x.read"},
		"no permission":    {Action: "x.read"},
		"bad action":       {Action: "X Read", Permission: "x.read"},
		"bad target param": {Action: "x.read", Permission: "x.read", TargetParam: "nope"},
		"bad severity":     {Action: "x.read", Permission: "x.read", Severity: "loud"},
	}
	for name, spec := range bad {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("registration did not panic")
				}
			}()
			route.New("demo", nil, nil).Handle("GET /x/{id}", spec, func(*route.Call) {})
		})
	}
}

func TestOpaqueBodyTenantIsData(t *testing.T) {
	rec := &routetest.Recorder{}
	r := route.New("demo", rec, nil)
	r.Handle("POST /kv", route.Spec{Action: "kv.written", Permission: "demo.write", OpaqueBody: true}, func(c *route.Call) {
		c.JSON(http.StatusOK, map[string]interface{}{"tenant": c.Tenant})
	})
	w := serve(t, r, "POST", "/kv", `{"tenant_id":"someone-else","x":1}`, claims("t1", "demo.write"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"tenant":"t1"`) {
		t.Fatalf("opaque body treated as a tenant claim: %d %s", w.Code, w.Body)
	}
}

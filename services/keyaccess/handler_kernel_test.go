package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/tenantcheck"
)

// memStore keeps one tenant's settings, rules and decisions in memory.
type memStore struct {
	settings  map[string]KeyAccessSettings
	rules     []KeyAccessRule
	decisions []KeyAccessDecision
}

func newMemStore() *memStore { return &memStore{settings: map[string]KeyAccessSettings{}} }

func (m *memStore) GetSettings(_ context.Context, tenant string) (KeyAccessSettings, error) {
	s, ok := m.settings[tenant]
	if !ok {
		return KeyAccessSettings{}, errNotFound
	}
	return s, nil
}
func (m *memStore) UpsertSettings(_ context.Context, s KeyAccessSettings) (KeyAccessSettings, error) {
	m.settings[s.TenantID] = s
	return s, nil
}
func (m *memStore) ListRules(context.Context, string) ([]KeyAccessRule, error) { return m.rules, nil }
func (m *memStore) UpsertRule(_ context.Context, r KeyAccessRule) (KeyAccessRule, error) {
	m.rules = append(m.rules, r)
	return r, nil
}
func (m *memStore) DeleteRule(context.Context, string, string) error { return nil }
func (m *memStore) CreateDecision(_ context.Context, d KeyAccessDecision) error {
	m.decisions = append(m.decisions, d)
	return nil
}
func (m *memStore) ListDecisions(context.Context, string, string, string, int) ([]KeyAccessDecision, error) {
	return m.decisions, nil
}

func kernelHandler() (*Handler, *memStore, *routetest.Recorder) {
	store := newMemStore()
	rec := &routetest.Recorder{}
	return NewHandler(NewService(store, nil), rec, nil), store, rec
}

func call(h *Handler, method, target, body string, c *pkgauth.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), c))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func servicePrincipal(clientID string) *pkgauth.Claims {
	return &pkgauth.Claims{Role: "client-service", ClientID: clientID, TenantID: tenantcheck.InternalServiceTenant(),
		Permissions: []string{tenantcheck.ServicePermission}}
}

// Every key-access route refuses an unauthenticated caller, a caller without
// the permission and a caller naming another tenant, and audits each refusal
// (before 6.9.0-beta none of them checked a permission or bound the tenant).
func TestKeyAccessRefusalsAudited(t *testing.T) {
	h, _, rec := kernelHandler()
	routetest.RefusalsAudited(t, h.router, rec)
}

// Only the ekm, cloud and hyok service identities get a decision, each for
// its own service name. A tenant administrator holding "*", another service
// identity, and an evaluator naming another service are refused and audited.
func TestEvaluateRestrictedToEvaluatorIdentities(t *testing.T) {
	h, store, rec := kernelHandler()
	body := `{"tenant_id":"t1","service":"ekm","operation":"decrypt","key_id":"k1"}`
	refused := []struct {
		name   string
		claims *pkgauth.Claims
		body   string
		reason string
	}{
		{"tenant admin", &pkgauth.Claims{UserID: "admin", TenantID: "t1", Permissions: []string{"*"}}, body, reasonEvaluator},
		{"other service", servicePrincipal("kms-keycore"), body, reasonEvaluator},
		{"forged kms- client outside the service tenant", &pkgauth.Claims{Role: "client-service", ClientID: "kms-ekm", TenantID: "t1",
			Permissions: []string{tenantcheck.ServicePermission, permEvaluate}}, body, reasonEvaluator},
		{"evaluator naming another service", servicePrincipal("kms-cloud"), body, reasonServiceMismatch},
	}
	for _, tc := range refused {
		w := call(h, "POST", "/key-access/evaluate", tc.body, tc.claims)
		ev := rec.Last(t)
		if w.Code != http.StatusForbidden || ev.Action != "decision_evaluated" || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != tc.reason {
			t.Fatalf("%s: status %d, event %+v", tc.name, w.Code, ev)
		}
	}
	if len(store.decisions) != 0 {
		t.Fatalf("refused callers recorded %d decisions", len(store.decisions))
	}

	w := call(h, "POST", "/key-access/evaluate", `{"tenant_id":"t1","operation":"decrypt","key_id":"k1"}`, servicePrincipal("kms-hyok-proxy"))
	if w.Code != http.StatusOK {
		t.Fatalf("hyok evaluate: %d %s", w.Code, w.Body.String())
	}
	if len(store.decisions) != 1 || store.decisions[0].Service != "hyok" || store.decisions[0].TenantID != "t1" {
		t.Fatalf("decision %+v, want service hyok in t1", store.decisions)
	}
	ev := rec.Last(t)
	if ev.Event.Result != route.ResultSuccess || ev.Event.TargetID != "k1" || ev.Event.Details["decision"] != "allow" || ev.Event.ActorID != "kms-hyok-proxy" {
		t.Fatalf("event %+v", ev)
	}
}

// With the policy enforced, a request without a justification code is denied
// and the decision is audited with its reason.
func TestEvaluateDeniesUnjustifiedRequest(t *testing.T) {
	h, store, rec := kernelHandler()
	admin := &pkgauth.Claims{UserID: "admin", TenantID: "t1", Permissions: []string{permWrite}}
	if w := call(h, "PUT", "/key-access/settings", `{"enabled":true,"mode":"enforce","require_justification_code":true,"updated_by":"forged"}`, admin); w.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", w.Code, w.Body.String())
	}
	if store.settings["t1"].UpdatedBy != "admin" {
		t.Fatalf("updated_by %q, want the verified caller", store.settings["t1"].UpdatedBy)
	}
	w := call(h, "POST", "/key-access/evaluate", `{"tenant_id":"t1","operation":"decrypt","key_id":"k1"}`, servicePrincipal("kms-ekm"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"deny"`) {
		t.Fatalf("evaluate: %d %s", w.Code, w.Body.String())
	}
	ev := rec.Last(t)
	if ev.Event.Details["decision"] != "deny" || ev.Event.Details["decision_reason"] != "missing_justification_code" {
		t.Fatalf("event details %+v", ev.Event.Details)
	}
}

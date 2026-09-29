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

func kernelHandler(t *testing.T) (*Handler, *memStore, *routetest.Recorder) {
	t.Helper()
	store := &memStore{policy: defaultAttestationPolicy("t1")}
	h := NewHandler(NewService(store, nil, "node-1"))
	rec := &routetest.Recorder{}
	h.SetAuditClient(rec)
	return h, store, rec
}

func call(h *Handler, method, target, body string, c *pkgauth.Claims) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), c))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// Every confidential route refuses an unauthenticated caller, a caller
// without the permission and a caller naming another tenant, and audits each
// refusal under its own action (before 6.9.0-beta only POST /release did).
func TestConfidentialRefusalsAudited(t *testing.T) {
	h, _, rec := kernelHandler(t)
	routetest.RefusalsAudited(t, h.router, rec)
}

// The requester recorded for an evaluation is the verified caller, never the
// body's requester field, and the tenant is the token's.
func TestEvaluateRecordsVerifiedCaller(t *testing.T) {
	h, store, rec := kernelHandler(t)
	caller := &pkgauth.Claims{UserID: "u-eval", TenantID: "t1", Permissions: []string{permEvaluate}}
	w := call(h, "POST", "/confidential/evaluate", `{"tenant_id":"t2","key_id":"k1","requester":"someone-else"}`, caller)
	if w.Code != http.StatusForbidden || rec.Last(t).Event.Details["reason"] != route.ReasonTenantMismatch {
		t.Fatalf("body tenant t2 with a t1 token: %d %s", w.Code, w.Body.String())
	}
	w = call(h, "POST", "/confidential/evaluate", `{"key_id":"k1","provider":"generic","requester":"someone-else"}`, caller)
	if w.Code != http.StatusOK {
		t.Fatalf("evaluate: %d %s", w.Code, w.Body.String())
	}
	if len(store.records) != 1 || store.records[0].Requester != "u-eval" || store.records[0].TenantID != "t1" {
		t.Fatalf("recorded %+v, want requester u-eval in t1", store.records)
	}
	ev := rec.Last(t)
	if ev.Action != "key_release_evaluated" || ev.Event.Result != route.ResultSuccess || ev.Event.TargetID != "k1" || ev.Event.Details["decision"] == nil {
		t.Fatalf("event %+v", ev)
	}
}

// A policy change is audited as policy_updated with what changed, and a
// reader can't make one.
func TestPolicyUpdateAuditedAndNeedsWrite(t *testing.T) {
	h, store, rec := kernelHandler(t)
	reader := &pkgauth.Claims{UserID: "u-r", TenantID: "t1", Permissions: []string{permRead}}
	if w := call(h, "PUT", "/confidential/policy", `{"enabled":false}`, reader); w.Code != http.StatusForbidden {
		t.Fatalf("reader changed the policy: %d", w.Code)
	}
	writer := &pkgauth.Claims{UserID: "u-w", TenantID: "t1", Permissions: []string{permWrite}}
	if w := call(h, "PUT", "/confidential/policy", `{"enabled":false,"provider":"aws_nitro_enclaves","updated_by":"forged"}`, writer); w.Code != http.StatusOK {
		t.Fatalf("policy update: %d %s", w.Code, w.Body.String())
	}
	ev := rec.Last(t)
	if ev.Action != "policy_updated" || ev.Event.Result != route.ResultSuccess || ev.Event.Details["provider"] != "aws_nitro_enclaves" {
		t.Fatalf("event %+v", ev)
	}
	if store.policy.UpdatedBy != "u-w" {
		t.Fatalf("updated_by %q, want the verified caller", store.policy.UpdatedBy)
	}
}

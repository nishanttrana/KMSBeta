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

func newAuditedSBOMHandler(t *testing.T) (*Handler, *Service, *routetest.Recorder) {
	t.Helper()
	svc, _, _, _, _, _ := newSBOMService(t)
	rec := &routetest.Recorder{}
	return NewHandler(svc, rec, nil), svc, rec
}

func TestSBOMRoutesRefusalsAudited(t *testing.T) {
	h, _, rec := newAuditedSBOMHandler(t)
	routetest.RefusalsAudited(t, h.router, rec)
}

func serve(h http.Handler, claims *pkgauth.Claims, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	asCaller(h, claims).ServeHTTP(rr, req)
	return rr
}

func expectRefused(t *testing.T, rec *routetest.Recorder, action, reason string) {
	t.Helper()
	got := rec.Last(t)
	if got.Action != action || got.Event.Result != route.ResultRefused || got.Event.Details["reason"] != reason {
		t.Fatalf("audited %s result=%s reason=%v, want %s refused %s", got.Action, got.Event.Result, got.Event.Details["reason"], action, reason)
	}
}

// A caller can no longer generate a CBOM for another tenant by naming it in
// the body (it was taken from the body unchecked before 1.33.0-beta).
func TestCBOMGenerateCrossTenantRefusedAndAudited(t *testing.T) {
	h, svc, rec := newAuditedSBOMHandler(t)
	for name, tc := range map[string]struct{ path, body string }{
		"body":  {"/cbom/generate", `{"tenant_id":"tenant-b","trigger":"manual"}`},
		"query": {"/cbom/generate?tenant_id=tenant-b", `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			rec.Reset()
			rr := serve(h, adminOf("tenant-a"), http.MethodPost, tc.path, tc.body)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", rr.Code, rr.Body.String())
			}
			expectRefused(t, rec, "cbom_generate_requested", route.ReasonTenantMismatch)
			if ev := rec.Last(t).Event; ev.TenantID != "tenant-a" || ev.Details["requested_tenant"] != "tenant-b" {
				t.Fatalf("refusal recorded under %q for %v", ev.TenantID, ev.Details["requested_tenant"])
			}
		})
	}
	if items, _ := svc.store.ListCBOMSnapshots(context.Background(), "tenant-b", 10); len(items) != 0 {
		t.Fatalf("a CBOM was generated for tenant-b: %d snapshots", len(items))
	}
}

func TestCBOMGenerateBindsTokenTenant(t *testing.T) {
	h, svc, rec := newAuditedSBOMHandler(t)
	rr := serve(h, adminOf("tenant-a"), http.MethodPost, "/cbom/generate", `{"trigger":"manual"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	ev := rec.Last(t)
	if ev.Action != "cbom_generate_requested" || ev.Event.Result != route.ResultSuccess || ev.Event.TenantID != "tenant-a" || ev.Event.ActorID != "u-tenant-a" {
		t.Fatalf("audited %s result=%s tenant=%s actor=%s", ev.Action, ev.Event.Result, ev.Event.TenantID, ev.Event.ActorID)
	}
	if items, _ := svc.store.ListCBOMSnapshots(context.Background(), "tenant-a", 10); len(items) != 1 {
		t.Fatalf("want 1 snapshot for the token's tenant, got %d", len(items))
	}
}

// Internal service principals act for the tenant the request names.
func TestCBOMGenerateServicePrincipalActsForRequestTenant(t *testing.T) {
	h, svc, _ := newAuditedSBOMHandler(t)
	principal := &pkgauth.Claims{
		Role: "client-service", ClientID: "kms-compliance", TenantID: tenantcheck.InternalServiceTenant(),
		Permissions: []string{tenantcheck.ServicePermission},
	}
	rr := serve(h, principal, http.MethodPost, "/cbom/generate", `{"tenant_id":"tenant-b"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if items, _ := svc.store.ListCBOMSnapshots(context.Background(), "tenant-b", 10); len(items) != 1 {
		t.Fatalf("want 1 snapshot for tenant-b, got %d", len(items))
	}
}

// The platform SBOM and its advisories are shared; another tenant's admin
// may read them but not change them.
func TestSBOMPlatformWritesRefusedOutsidePlatformTenant(t *testing.T) {
	h, _, rec := newAuditedSBOMHandler(t)
	cases := []struct{ method, path, body, action string }{
		{http.MethodPost, "/sbom/generate", `{}`, "sbom_generate_requested"},
		{http.MethodPost, "/sbom/advisories", `{"id":"CVE-2026-1","component":"x","severity":"high"}`, "sbom_advisory_saved"},
		{http.MethodDelete, "/sbom/advisories/CVE-2026-1", ``, "sbom_advisory_deleted"},
	}
	for _, tc := range cases {
		rec.Reset()
		rr := serve(h, adminOf("tenant-a"), tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: status %d, want 403: %s", tc.method, tc.path, rr.Code, rr.Body.String())
		}
		expectRefused(t, rec, tc.action, reasonPlatformTenant)
	}
	if rr := serve(h, adminOf("tenant-a"), http.MethodGet, "/sbom/advisories", ``); rr.Code != http.StatusOK {
		t.Fatalf("read refused: %d %s", rr.Code, rr.Body.String())
	}
}

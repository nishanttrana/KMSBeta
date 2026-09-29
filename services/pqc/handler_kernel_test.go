package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// Every pqc route authenticates, binds the tenant to the token, checks
// pqc.read/pqc.write and audits refusals (before 5.2.0-beta the service
// took the tenant from the query or body and checked no permission).
func TestPQCRoutesRefusalsAudited(t *testing.T) {
	svc, _, _, _ := newPQCService(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, NewHandler(svc, rec, nil).router, rec)
}

// The actor recorded for a plan execution is the verified caller, never a
// name in the request body; a body naming another tenant is refused.
func TestPQCActorAndTenantComeFromTheToken(t *testing.T) {
	svc, _, pub, keycore := newPQCService(t)
	rec := &routetest.Recorder{}
	h := asCaller(NewHandler(svc, rec, nil), adminOf("t1"))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rr
	}
	if rr := call(http.MethodPost, "/pqc/scan", `{"tenant_id":"t2","trigger":"x"}`); rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant scan: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Event.Result != "refused" || e.Event.Details["reason"] != "tenant_mismatch" {
		t.Fatalf("tenant refusal event %+v", e)
	}
	if rr := call(http.MethodPost, "/pqc/scan", `{"trigger":"x"}`); rr.Code != http.StatusAccepted {
		t.Fatalf("scan: %d %s", rr.Code, rr.Body)
	}
	rr := call(http.MethodPost, "/pqc/migration/plans", `{"name":"p","created_by":"mallory"}`)
	if rr.Code != http.StatusCreated || strings.Contains(rr.Body.String(), "mallory") {
		t.Fatalf("create plan: %d %s", rr.Code, rr.Body)
	}
	plans, _ := svc.ListMigrationPlans(t.Context(), "t1", 10, 0)
	if len(plans) != 1 || plans[0].CreatedBy != "u-t1" {
		t.Fatalf("plan creator: %+v", plans)
	}
	if rr := call(http.MethodPost, "/pqc/migration/plans/"+plans[0].ID+"/execute", `{"actor":"mallory"}`); rr.Code != http.StatusOK {
		t.Fatalf("execute: %d %s", rr.Code, rr.Body)
	}
	keycore.mu.Lock()
	for _, req := range keycore.created {
		if req["created_by"] != "u-t1" {
			t.Fatalf("successor created by %v, want the verified caller", req["created_by"])
		}
	}
	keycore.mu.Unlock()
	if e := rec.Last(t); e.Action != "plan_execute_requested" || e.Event.Result != "success" {
		t.Fatalf("execute event %+v", e)
	}
	_ = pub
	// A reader cannot execute.
	reader := &pkgauth.Claims{UserID: "r1", TenantID: "t1", Permissions: []string{"pqc.read"}}
	rr = httptest.NewRecorder()
	asCaller(NewHandler(svc, rec, nil), reader).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/pqc/migration/plans/"+plans[0].ID+"/execute", strings.NewReader(`{}`)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("reader executed a plan: %d", rr.Code)
	}
}

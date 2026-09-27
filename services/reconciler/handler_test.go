package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	pkgreconciler "vecta-kms/pkg/reconciler"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

func newTestRouter(rec *routetest.Recorder) *route.Router {
	return newRouter(func() []pkgreconciler.Status { return []pkgreconciler.Status{{Name: "tenant"}} }, rec, nil)
}

func TestReconcilerRoutesRefusalsAudited(t *testing.T) {
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, newTestRouter(rec), rec)
}

// A health.read holder reads the status, and the read is audited; a
// controller that has not run yet carries no last_run_at.
func TestReconcilerStatusReadAudited(t *testing.T) {
	rec := &routetest.Recorder{}
	admin := &pkgauth.Claims{UserID: "u-1", TenantID: "root", Role: "admin", Permissions: []string{permHealthRead}}
	w := httptest.NewRecorder()
	newTestRouter(rec).ServeHTTP(w, routetest.Request("GET /reconciler/status", admin, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := rec.Last(t); got.Action != "status_read" || got.Event.Result != route.ResultSuccess {
		t.Fatalf("audited %s result=%s", got.Action, got.Event.Result)
	}
	if body := w.Body.String(); !strings.Contains(body, `"name":"tenant"`) || strings.Contains(body, "last_run_at") {
		t.Fatalf("body %s", body)
	}
}

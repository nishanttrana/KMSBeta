package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The schedule routes go through the route kernel: every refusal is
// audited, a tenant other than root is refused whatever its permissions, a
// schedule nobody could take a key from is refused with its reason, and
// the saving administrator is the verified caller, never the body.
func TestBackupScheduleRoutes(t *testing.T) {
	h := &Handler{svc: NewService(newGovernanceStore(t), nil, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050")}
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	r := h.backupScheduleRouter()
	routetest.RefusalsAudited(t, r, rec)

	call := func(method, target, body string, claims *pkgauth.Claims) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	rootAdmin := &pkgauth.Claims{UserID: "admin-1", TenantID: "root", Permissions: []string{"*"}}
	tenantAdmin := &pkgauth.Claims{UserID: "t-admin", TenantID: "t1", Permissions: []string{"*"}}

	if w := call(http.MethodGet, "/governance/backups/schedules?tenant_id=t1", "", tenantAdmin); w.Code != http.StatusForbidden {
		t.Fatalf("a tenant administrator: %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "not_root_tenant" {
		t.Fatalf("refusal event %+v", ev.Event)
	}
	w := call(http.MethodPost, "/governance/backups/schedules?tenant_id=root",
		`{"name":"nightly","scope":"system","interval_hours":24,"retain_count":7,"key_protection":"software"}`, rootAdmin)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "nobody is present") {
		t.Fatalf("a software-key schedule: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "invalid_schedule" {
		t.Fatalf("invalid schedule event %+v", ev.Event)
	}
	w = call(http.MethodGet, "/governance/backups/schedules?tenant_id=root", "", rootAdmin)
	var out struct {
		Items []BackupSchedule `json:"items"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Items) != 0 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "backup_schedules_listed" || ev.Event.Result != "success" {
		t.Fatalf("list event %s %+v", ev.Action, ev.Event)
	}
}

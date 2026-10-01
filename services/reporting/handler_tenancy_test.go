package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauditmw "vecta-kms/pkg/auditmw"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
	"vecta-kms/pkg/tenantcheck"
)

func newAuditedReportingHandler(t *testing.T) (*Handler, *Service, *routetest.Recorder) {
	t.Helper()
	svc, _, _, _, _, _ := newReportingService(t)
	rec := &routetest.Recorder{}
	return NewHandler(svc, rec, nil), svc, rec
}

func TestReportingRoutesRefusalsAudited(t *testing.T) {
	h, _, rec := newAuditedReportingHandler(t)
	routetest.RefusalsAudited(t, h.router, rec)
}

func serve(h http.Handler, claims *pkgauth.Claims, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rr := httptest.NewRecorder()
	asCaller(h, claims).ServeHTTP(rr, req)
	return rr
}

// Before 1.33.0-beta the tenant came from the body or query unchecked, so a
// caller could queue reports over another tenant's alerts and posture.
func TestGenerateReportCrossTenantRefusedAndAudited(t *testing.T) {
	h, svc, rec := newAuditedReportingHandler(t)
	for name, tc := range map[string]struct{ path, body string }{
		"body":  {"/reports/generate", `{"tenant_id":"tenant-b","template_id":"alert_summary","format":"json"}`},
		"query": {"/reports/generate?tenant_id=tenant-b", `{"template_id":"alert_summary","format":"json"}`},
	} {
		t.Run(name, func(t *testing.T) {
			rec.Reset()
			rr := serve(h, adminOf("tenant-a"), http.MethodPost, tc.path, tc.body)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", rr.Code, rr.Body.String())
			}
			got := rec.Last(t)
			if got.Action != "report_requested" || got.Event.Result != route.ResultRefused || got.Event.Details["reason"] != route.ReasonTenantMismatch {
				t.Fatalf("audited %s result=%s reason=%v", got.Action, got.Event.Result, got.Event.Details["reason"])
			}
			if got.Event.TenantID != "tenant-a" || got.Event.Details["requested_tenant"] != "tenant-b" {
				t.Fatalf("refusal recorded under %q for %v", got.Event.TenantID, got.Event.Details["requested_tenant"])
			}
		})
	}
	if jobs, _ := svc.ListReportJobs(context.Background(), "tenant-b", 10, 0); len(jobs) != 0 {
		t.Fatalf("a report job was queued for tenant-b: %d", len(jobs))
	}
}

// The requester is the verified caller; a claimed requested_by is rejected
// rather than silently recorded.
func TestGenerateReportRequesterIsVerifiedCaller(t *testing.T) {
	h, _, rec := newAuditedReportingHandler(t)
	rr := serve(h, adminOf("tenant-a"), http.MethodPost, "/reports/generate", `{"template_id":"alert_summary","format":"json","requested_by":"someone-else"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("claimed requested_by: status %d, want 400: %s", rr.Code, rr.Body.String())
	}
	rr = serve(h, adminOf("tenant-a"), http.MethodPost, "/reports/generate", `{"template_id":"alert_summary","format":"json"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Job ReportJob `json:"job"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Job.RequestedBy != "u-tenant-a" || out.Job.TenantID != "tenant-a" {
		t.Fatalf("job requested_by=%q tenant=%q", out.Job.RequestedBy, out.Job.TenantID)
	}
	ev := rec.Last(t)
	if ev.Action != "report_requested" || ev.Event.Result != route.ResultSuccess || ev.Event.ActorID != "u-tenant-a" || ev.Event.TargetID != out.Job.ID {
		t.Fatalf("audited %s result=%s actor=%s target=%s", ev.Action, ev.Event.Result, ev.Event.ActorID, ev.Event.TargetID)
	}
}

// The deleting actor is the verified caller, not the actor query parameter
// or X-Actor-ID header; another tenant's job can't be deleted.
func TestDeleteReportJobActorAndTenancy(t *testing.T) {
	h, svc, rec := newAuditedReportingHandler(t)
	job, err := svc.GenerateReport(context.Background(), "tenant-a", "alert_summary", "json", "u-tenant-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	waitForJob(t, svc, "tenant-a", job.ID)

	rec.Reset()
	rr := serve(h, adminOf("tenant-b"), http.MethodDelete, "/reports/jobs/"+job.ID+"?tenant_id=tenant-a", "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant delete: status %d, want 403", rr.Code)
	}
	if got := rec.Last(t); got.Action != "report_deleted" || got.Event.Details["reason"] != route.ReasonTenantMismatch {
		t.Fatalf("audited %s reason=%v", got.Action, got.Event.Details["reason"])
	}
	// Under the caller's own tenant the job doesn't exist.
	if rr := serve(h, adminOf("tenant-b"), http.MethodDelete, "/reports/jobs/"+job.ID, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("delete under own tenant: status %d, want 404", rr.Code)
	}

	rec.Reset()
	rr = serve(h, adminOf("tenant-a"), http.MethodDelete, "/reports/jobs/"+job.ID+"?actor=forged", "", "X-Actor-ID", "forged")
	if rr.Code != http.StatusOK {
		t.Fatalf("delete: status %d: %s", rr.Code, rr.Body.String())
	}
	ev := rec.Last(t)
	if ev.Action != "report_deleted" || ev.Event.Result != route.ResultSuccess || ev.Event.ActorID != "u-tenant-a" || ev.Event.TargetID != job.ID {
		t.Fatalf("audited %s result=%s actor=%s target=%s", ev.Action, ev.Event.Result, ev.Event.ActorID, ev.Event.TargetID)
	}
	if ev.Event.Details["template_id"] != "alert_summary" {
		t.Fatalf("details %v", ev.Event.Details)
	}
}

func TestReportingServicePrincipalActsForRequestTenant(t *testing.T) {
	h, svc, _ := newAuditedReportingHandler(t)
	principal := &pkgauth.Claims{
		Role: "client-service", ClientID: "kms-governance", TenantID: tenantcheck.InternalServiceTenant(),
		Permissions: []string{tenantcheck.ServicePermission},
	}
	rr := serve(h, principal, http.MethodPost, "/reports/generate?tenant_id=tenant-b", `{"template_id":"alert_summary","format":"json"}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if jobs, _ := svc.ListReportJobs(context.Background(), "tenant-b", 10, 0); len(jobs) != 1 || jobs[0].RequestedBy != "kms-governance" {
		t.Fatalf("want one job for tenant-b requested by kms-governance, got %+v", jobs)
	}
}

// Alert operations record the verified caller as the acting user; the old
// body actor field is rejected.
func TestAlertOperationActorIsVerifiedCaller(t *testing.T) {
	h, svc, rec := newAuditedReportingHandler(t)
	alert, err := svc.ingestAuditEvent(context.Background(), "tenant-a", map[string]interface{}{
		"id": "ev-1", "action": "key.exported", "service": "keycore", "target_id": "k1", "timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil || alert.ID == "" {
		t.Fatalf("seed alert: %v %+v", err, alert)
	}
	if rr := serve(h, adminOf("tenant-a"), http.MethodPut, "/alerts/"+alert.ID+"/acknowledge", `{"actor":"forged"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("claimed actor: status %d, want 400", rr.Code)
	}
	if rr := serve(h, adminOf("tenant-a"), http.MethodPut, "/alerts/"+alert.ID+"/resolve", `{"note":"done"}`); rr.Code != http.StatusOK {
		t.Fatalf("resolve: status %d: %s", rr.Code, rr.Body.String())
	}
	ev := rec.Last(t)
	if ev.Action != "alert_updated" || ev.Event.Details["operation"] != "resolve" || ev.Event.TargetID != alert.ID {
		t.Fatalf("audited %s op=%v target=%s", ev.Action, ev.Event.Details["operation"], ev.Event.TargetID)
	}
	got, _, err := svc.GetAlert(context.Background(), "tenant-a", alert.ID)
	if err != nil || got.ResolvedBy != "u-tenant-a" {
		t.Fatalf("resolved_by=%q err=%v", got.ResolvedBy, err)
	}
}

// The SSE feed flushes through the kernel's and the audit safety net's
// response wrappers (it could not before: neither exposed Flush).
func TestAlertsFeedStreamsThroughWrappers(t *testing.T) {
	h, svc, _ := newAuditedReportingHandler(t)
	srv := httptest.NewServer(pkgauditmw.Wrap(asCaller(h, adminOf("tenant-a")), &nopReportingPublisher{}, "reporting"))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/alerts/feed", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var seen strings.Builder
	buf := make([]byte, 512)
	published := false
	for !strings.Contains(seen.String(), "event: alert") {
		n, err := resp.Body.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			t.Fatalf("stream ended before a live alert arrived (%v): %q", err, seen.String())
		}
		if !published && strings.Contains(seen.String(), "event: ready") {
			svc.hub.Publish("tenant-a", Alert{ID: "alert-live"})
			published = true
		}
	}
}

func waitForJob(t *testing.T, svc *Service, tenant, id string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if j, err := svc.GetReportJob(context.Background(), tenant, id); err == nil && j.Status == "completed" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("report job %s did not complete", id)
}

// A malformed chart window is refused on every statistics route, and each
// refusal is audited with its reason; a valid window is audited as read.
func TestAlertStatsWindowRefusedAndAudited(t *testing.T) {
	h, _, rec := newAuditedReportingHandler(t)
	claims := &pkgauth.Claims{UserID: "analyst", TenantID: "t1", Permissions: []string{permRead}}
	for _, p := range []string{"/alerts/stats", "/alerts/stats/mttr", "/alerts/stats/mttd", "/alerts/stats/top-sources"} {
		if rr := serve(h, claims, http.MethodGet, p+"?tenant_id=t1&from=last-week", ""); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", p, rr.Code)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "bad_window" {
			t.Fatalf("%s: refusal audited as %+v", p, ev)
		}
	}
	from := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	if rr := serve(h, claims, http.MethodGet, "/alerts/stats?tenant_id=t1&from="+from, ""); rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if ev := rec.Last(t); ev.Action != "alert_stats_read" || ev.Event.Result != "success" {
		t.Fatalf("audited %+v", ev)
	}
}

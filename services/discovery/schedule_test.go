package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// stubAuthority answers as auth would for the schedule's authorizing user.
type stubAuthority struct {
	active  bool
	missing []string
	err     error
	asked   []string
}

func (a *stubAuthority) Authority(_ context.Context, tenantID, userID string, perms []string) (bool, []string, error) {
	a.asked = append(a.asked, tenantID+"/"+userID+"/"+strings.Join(perms, ","))
	return a.active, a.missing, a.err
}

func scheduled(t *testing.T, rec *routetest.Recorder) []routetest.Recorded {
	t.Helper()
	var out []routetest.Recorded
	for _, e := range rec.Events() {
		if e.Action == "scheduled_scan" {
			out = append(out, e)
		}
	}
	return out
}

// Saving a schedule needs discovery.write and a signed-in user, and a bad
// one is refused; each refusal is audited.
func TestScheduleRoutesAudited(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	rec := &routetest.Recorder{}
	h := NewHandler(svc, rec, nil)
	put := func(who *pkgauth.Claims, body string) int {
		return serveAs(h, who, http.MethodPut, "/discovery/schedule", body).Code
	}
	if rr := serveAs(h, testReadonly, http.MethodGet, "/discovery/schedule", ""); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"enabled":false`) {
		t.Fatalf("unsaved schedule: %d %s", rr.Code, rr.Body)
	}
	if put(testReadonly, `{"enabled":true,"interval_hours":24,"sources":["certs"]}`) != http.StatusForbidden {
		t.Fatal("saved as discovery.read")
	}
	expectAudit(t, rec, "schedule_update", route.ResultRefused, route.ReasonPermissionDenied)
	// An API client and a platform service have no user to re-check.
	client := &pkgauth.Claims{ClientID: "ci-bot", TenantID: "t1", Permissions: []string{"discovery.write"}}
	service := &pkgauth.Claims{Role: "client-service", ClientID: "kms-compliance", TenantID: "root", Permissions: []string{"service.internal"}}
	for _, who := range []*pkgauth.Claims{client, service} {
		if code := serveAs(h, who, http.MethodPut, "/discovery/schedule?tenant_id=t1", `{"enabled":true,"interval_hours":24,"sources":["certs"]}`).Code; code != http.StatusForbidden {
			t.Fatalf("%s saved a schedule: %d", who.ClientID, code)
		}
		expectAudit(t, rec, "schedule_update", route.ResultRefused, "user_required")
	}
	for _, body := range []string{
		`{"enabled":true,"interval_hours":0,"sources":["certs"]}`,
		`{"enabled":true,"interval_hours":100000,"sources":["certs"]}`,
		`{"enabled":true,"interval_hours":24,"sources":[]}`,
		`{"enabled":true,"interval_hours":24,"sources":["upload"]}`,
	} {
		if put(testWriter, body) != http.StatusBadRequest {
			t.Fatalf("accepted %s", body)
		}
		expectAudit(t, rec, "schedule_update", route.ResultRefused, "invalid_schedule")
	}
	if put(testWriter, `{"enabled":true,"interval_hours":6,"sources":["certs","git","certs"]}`) != http.StatusOK {
		t.Fatal("valid schedule refused")
	}
	expectAudit(t, rec, "schedule_update", route.ResultSuccess, "")
	sch, _ := svc.GetSchedule(context.Background(), "t1")
	if !sch.Enabled || sch.AuthorizedBy != "w" || strings.Join(sch.Sources, ",") != "certs,git" || time.Until(sch.NextRunAt) < 5*time.Hour || time.Until(sch.NextRunAt) > 7*time.Hour {
		t.Fatalf("saved %+v", sch)
	}
}

// A due schedule runs on its authorizer's standing authority: auth is asked
// before every run, a lost permission pauses the schedule and is audited,
// and an unanswered check postpones the run without pausing it.
func TestScheduleRunsOnCheckedAuthority(t *testing.T) {
	svc, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	rec := &routetest.Recorder{}
	svc.audit = rec
	auth := &stubAuthority{active: true}
	svc.authority = auth
	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }

	if _, err := svc.SaveSchedule(ctx, "t1", true, 6, []string{"certs"}, "alice"); err != nil {
		t.Fatal(err)
	}
	if n := svc.RunDueSchedules(ctx); n != 0 || len(auth.asked) != 0 {
		t.Fatalf("ran %d before it was due (asked %v)", n, auth.asked)
	}

	clock = clock.Add(6*time.Hour + time.Minute)
	if n := svc.RunDueSchedules(ctx); n != 1 {
		t.Fatalf("due schedule started %d scans", n)
	}
	svc.scans.Wait()
	if len(auth.asked) != 1 || auth.asked[0] != "t1/alice/discovery.write" {
		t.Fatalf("authority asked %v", auth.asked)
	}
	sch, _ := svc.GetSchedule(ctx, "t1")
	scan, err := svc.GetScan(ctx, "t1", sch.LastScanID)
	if err != nil || scan.Trigger != "scheduled" || scan.Status != "completed" || scan.ScanType != "certs" {
		t.Fatalf("scheduled scan %+v, %v", scan, err)
	}
	if !sch.NextRunAt.Equal(clock.Add(6*time.Hour)) || sch.PausedReason != "" {
		t.Fatalf("after a run %+v", sch)
	}
	if ev := scheduled(t, rec); len(ev) != 1 || ev[0].Event.Result != route.ResultSuccess || ev[0].Event.TargetID != scan.ID || ev[0].Event.Details["authorized_by"] != "alice" {
		t.Fatalf("scheduled_scan events %+v", ev)
	}
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("ran again before the next interval: %d", n)
	}

	// Auth doesn't answer: nothing runs, and the schedule is not paused.
	clock = clock.Add(7 * time.Hour)
	auth.err = errors.New("auth unreachable")
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("ran on unverified authority: %d", n)
	}
	sch, _ = svc.GetSchedule(ctx, "t1")
	if sch.PausedReason != "" || !sch.NextRunAt.Equal(clock.Add(scheduleRetry)) {
		t.Fatalf("after an unanswered check %+v", sch)
	}
	if ev := scheduled(t, rec); ev[len(ev)-1].Event.Result != route.ResultRefused || ev[len(ev)-1].Event.Details["reason"] != "authority_unknown" {
		t.Fatalf("unanswered check audited as %+v", ev[len(ev)-1].Event)
	}

	// Alice lost discovery.write: the schedule pauses and stops asking.
	clock = clock.Add(time.Hour)
	auth.err, auth.missing = nil, []string{"discovery.write"}
	scansBefore, _ := store.ListScans(ctx, "t1", 100, 0)
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("ran without the permission: %d", n)
	}
	sch, _ = svc.GetSchedule(ctx, "t1")
	if !strings.Contains(sch.PausedReason, "discovery.write") {
		t.Fatalf("not paused: %+v", sch)
	}
	if ev := scheduled(t, rec); ev[len(ev)-1].Event.Details["reason"] != "authority_revoked" {
		t.Fatalf("revoked authority audited as %+v", ev[len(ev)-1].Event)
	}
	asked := len(auth.asked)
	clock = clock.Add(48 * time.Hour)
	if n := svc.RunDueSchedules(ctx); n != 0 || len(auth.asked) != asked {
		t.Fatalf("a paused schedule ran or asked again: %d, %d checks", n, len(auth.asked)-asked)
	}
	if scansAfter, _ := store.ListScans(ctx, "t1", 100, 0); len(scansAfter) != len(scansBefore) {
		t.Fatal("a refused run created a scan")
	}

	// Saved again by someone who holds the permission: it resumes.
	auth.missing = nil
	if _, err := svc.SaveSchedule(ctx, "t1", true, 6, []string{"certs"}, "bob"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(7 * time.Hour)
	if n := svc.RunDueSchedules(ctx); n != 1 || auth.asked[len(auth.asked)-1] != "t1/bob/discovery.write" {
		t.Fatalf("resumed schedule: %d scans, asked %v", n, auth.asked[len(auth.asked)-1])
	}
	svc.scans.Wait()

	// An inactive user is refused the same way.
	auth.active = false
	clock = clock.Add(7 * time.Hour)
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("ran for an inactive user: %d", n)
	}
	// With no authority checker wired, nothing runs.
	svc.authority = nil
	_, _ = svc.SaveSchedule(ctx, "t2", true, 1, []string{"certs"}, "carol")
	clock = clock.Add(2 * time.Hour)
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("ran with no authority checker: %d", n)
	}
}

// A cluster member never runs schedules: the primary does, and its results
// replicate.
func TestScheduleSkippedOnClusterMember(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	auth := &stubAuthority{active: true}
	svc.authority = auth
	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }
	_, _ = svc.SaveSchedule(ctx, "t1", true, 1, []string{"certs"}, "alice")
	clock = clock.Add(2 * time.Hour)

	svc.primary = func(context.Context) bool { return false }
	if n := svc.RunDueSchedules(ctx); n != 0 || len(auth.asked) != 0 {
		t.Fatalf("member ran %d schedules (asked %v)", n, auth.asked)
	}
	if scans, _ := svc.ListScans(ctx, "t1", 10, 0); len(scans) != 0 {
		t.Fatalf("member wrote scans: %+v", scans)
	}
	svc.primary = func(context.Context) bool { return true }
	if n := svc.RunDueSchedules(ctx); n != 1 {
		t.Fatalf("primary ran %d schedules", n)
	}
	svc.scans.Wait()
}

// A disabled schedule never runs, and a due run waits while another scan is
// running for the tenant.
func TestScheduleDisabledAndBusy(t *testing.T) {
	svc, _, _ := newDiscoveryService(t)
	ctx := context.Background()
	svc.authority = &stubAuthority{active: true}
	clock := time.Now().UTC()
	svc.now = func() time.Time { return clock }
	_, _ = svc.SaveSchedule(ctx, "t1", false, 1, []string{"certs"}, "alice")
	clock = clock.Add(48 * time.Hour)
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("disabled schedule ran: %d", n)
	}
	_, _ = svc.SaveSchedule(ctx, "t1", true, 1, []string{"certs"}, "alice")
	clock = clock.Add(2 * time.Hour)
	block := make(chan struct{})
	svc.cloud = &testCloud{block: block}
	if _, err := svc.StartScan(ctx, ScanRequest{TenantID: "t1", ScanTypes: []string{"cloud"}}); err != nil {
		t.Fatal(err)
	}
	if n := svc.RunDueSchedules(ctx); n != 0 {
		t.Fatalf("scheduled scan started over a running one: %d", n)
	}
	if sch, _ := svc.GetSchedule(ctx, "t1"); !sch.NextRunAt.Equal(clock.Add(scheduleRetry)) || sch.PausedReason != "" {
		t.Fatalf("busy schedule %+v", sch)
	}
	close(block)
	svc.scans.Wait()
}

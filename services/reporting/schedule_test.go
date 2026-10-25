package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/authority"
)

// holderAuthority: the person holds everything asked.
type holderAuthority struct{}

func (holderAuthority) Authority(context.Context, string, string, []string) (authority.Answer, error) {
	return authority.Answer{Active: true, Missing: []string{}}, nil
}

type stubAuthority struct {
	answer authority.Answer
	err    error
}

func (a stubAuthority) Authority(context.Context, string, string, []string) (authority.Answer, error) {
	return a.answer, a.err
}

// eventRecorder keeps the scheduler's own events.
type eventRecorder struct{ events []pkgaudit.Event }

func (r *eventRecorder) Emit(_ context.Context, action string, e pkgaudit.Event) error {
	if action == "scheduled_report_run" {
		r.events = append(r.events, e)
	}
	return nil
}

func (r *eventRecorder) last(t *testing.T) pkgaudit.Event {
	t.Helper()
	if len(r.events) == 0 {
		t.Fatal("no scheduled_report_run event")
	}
	return r.events[len(r.events)-1]
}

// A schedule's cadence, template and format are checked against what the
// service produces, and it can be paused, edited, run now and deleted.
func TestScheduledReportLifecycle(t *testing.T) {
	h, svc, rec := newAuditedReportingHandler(t)
	svc.authority = holderAuthority{}
	runs := &eventRecorder{}
	svc.events = runs
	alice := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Permissions: []string{permRead, permWrite}}

	for _, body := range []string{
		`{"name":"x","template_id":"alert_summary","format":"pdf","schedule":"monthly"}`,
		`{"name":"x","template_id":"nope","format":"pdf","schedule":"daily"}`,
		`{"name":"x","template_id":"posture_summary","format":"csv","schedule":"daily"}`,
		`{"name":"","template_id":"alert_summary","format":"pdf","schedule":"daily"}`,
	} {
		if rr := serve(h, alice, http.MethodPost, "/reports/scheduled?tenant_id=t1", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d %s", body, rr.Code, rr.Body)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "invalid_schedule" {
			t.Fatalf("refusal audited as %+v", ev)
		}
	}
	rr := serve(h, alice, http.MethodPost, "/reports/scheduled?tenant_id=t1", `{"name":"weekly alerts","template_id":"alert_summary","format":"pdf","schedule":"weekly"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	var out struct {
		Item ScheduledReport `json:"item"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	id := out.Item.ID
	if out.Item.AuthorizedBy != "alice" || out.Item.NextRunAt.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("created %+v", out.Item)
	}

	rr = serve(h, alice, http.MethodPost, "/reports/scheduled/"+id+"/run?tenant_id=t1", ``)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Item.LastResult != "requested" || out.Item.LastJobID == "" {
		t.Fatalf("run now: %d %+v", rr.Code, out.Item)
	}
	if job, err := svc.GetReportJob(context.Background(), "t1", out.Item.LastJobID); err != nil || job.RequestedBy != "alice" {
		t.Fatalf("the run queued %+v %v", job, err)
	}
	if ev := runs.last(t); ev.Result != "success" || ev.Details["trigger"] != "manual:alice" || ev.Details["job_id"] != out.Item.LastJobID {
		t.Fatalf("run audited as %+v", ev)
	}

	bob := &pkgauth.Claims{UserID: "bob", TenantID: "t1", Permissions: []string{permRead, permWrite}}
	rr = serve(h, bob, http.MethodPatch, "/reports/scheduled/"+id+"?tenant_id=t1", `{"enabled":false,"schedule":"daily"}`)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != http.StatusOK || out.Item.Enabled || out.Item.Schedule != "daily" || out.Item.AuthorizedBy != "bob" {
		t.Fatalf("edit: %d %+v", rr.Code, out.Item)
	}
	if rr := serve(h, bob, http.MethodDelete, "/reports/scheduled/"+id+"?tenant_id=t1", ``); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if _, err := svc.store.GetScheduledReport(context.Background(), "t1", id); !errors.Is(err, errNotFound) {
		t.Fatalf("still stored: %v", err)
	}
	if rr := serve(h, bob, http.MethodDelete, "/reports/scheduled/"+id+"?tenant_id=t1", ``); rr.Code != http.StatusNotFound {
		t.Fatalf("delete twice: %d", rr.Code)
	}
}

// A scheduled run happens only on the saver's authority now: revoked pauses
// it, auth not answering postpones it, and nothing is queued either way.
func TestScheduledReportNeedsTheSaversAuthority(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		auth   authority.Checker
		by     string
		reason string
		paused bool
	}{
		"revoked":   {stubAuthority{answer: authority.Answer{Active: true, Missing: []string{permWrite}}}, "alice", authority.ReasonRevoked, true},
		"inactive":  {stubAuthority{answer: authority.Answer{Active: false, Missing: []string{}}}, "alice", authority.ReasonRevoked, true},
		"no one":    {holderAuthority{}, "", authority.ReasonRevoked, true},
		"auth down": {stubAuthority{err: errors.New("unreachable")}, "alice", authority.ReasonUnknown, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, svc, _ := newAuditedReportingHandler(t)
			runs := &eventRecorder{}
			svc.events, svc.authority = runs, holderAuthority{}
			str := func(v string) *string { return &v }
			sched, err := svc.ScheduleReport(ctx, "t1", tc.by, scheduledReportInput{Name: str("d"), TemplateID: str("alert_summary"), Format: str("json"), Schedule: str("daily")})
			if err != nil {
				t.Fatal(err)
			}
			sched.NextRunAt = time.Now().UTC().Add(-time.Minute)
			_ = svc.store.SaveScheduledReport(ctx, sched)
			svc.authority = tc.auth
			if err := svc.RunDueSchedules(ctx); err != nil {
				t.Fatal(err)
			}
			got, _ := svc.store.GetScheduledReport(ctx, "t1", sched.ID)
			if got.LastResult != "refused" || got.LastJobID != "" || (got.PausedReason != "") != tc.paused {
				t.Fatalf("after refusal: %+v", got)
			}
			if jobs, _ := svc.ListReportJobs(ctx, "t1", 10, 0); len(jobs) != 0 {
				t.Fatalf("a refused run queued %d jobs", len(jobs))
			}
			if ev := runs.last(t); ev.Result != "refused" || ev.Details["reason"] != tc.reason {
				t.Fatalf("refusal audited as %+v", ev)
			}
			if tc.paused {
				if due, _ := svc.store.ListDueScheduledReports(ctx, time.Now().UTC().Add(48*time.Hour), 10); len(due) != 0 {
					t.Fatal("a paused schedule is still due")
				}
			}
		})
	}
}

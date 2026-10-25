package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

type scheduleAuthority struct {
	answer authority.Answer
	err    error
}

func (a scheduleAuthority) Authority(context.Context, string, string, []string) (authority.Answer, error) {
	if a.answer.Missing == nil {
		a.answer.Missing = []string{}
	}
	return a.answer, a.err
}

// runEvents keeps the payloads of assessment_schedule_run events.
type runEvents struct{ data []map[string]interface{} }

func (r *runEvents) Publish(_ context.Context, subject string, raw []byte) error {
	if subject != "audit.compliance.assessment_schedule_run" {
		return nil
	}
	var env struct {
		Data map[string]interface{} `json:"data"`
	}
	_ = json.Unmarshal(raw, &env)
	r.data = append(r.data, env.Data)
	return nil
}

func scheduleCall(h http.Handler, claims *pkgauth.Claims, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// Before 13.66.0-beta the save took tenant_id from the body unchecked: a
// caller could set another tenant's schedule. The kernel refuses it now.
func TestAssessmentScheduleIsTheCallersTenantOnly(t *testing.T) {
	h, svc, _, _, _, _, _ := newComplianceHandler(t)
	a := &pkgauth.Claims{UserID: "admin-a", TenantID: "tenant-a", Permissions: []string{"*"}}
	if w := scheduleCall(h, a, http.MethodPut, "/compliance/assessment/schedule", `{"tenant_id":"tenant-b","enabled":true,"frequency":"hourly"}`); w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant save: %d %s", w.Code, w.Body)
	}
	if got, _ := svc.store.GetAssessmentSchedule(context.Background(), "tenant-b"); got.Enabled {
		t.Fatal("tenant-b's schedule was changed by tenant-a")
	}
	viewer := &pkgauth.Claims{UserID: "viewer", TenantID: "tenant-a", Permissions: []string{"compliance.assessment.read"}}
	if w := scheduleCall(h, viewer, http.MethodPut, "/compliance/assessment/schedule", `{"enabled":true,"frequency":"daily"}`); w.Code != http.StatusForbidden {
		t.Fatalf("save without compliance.assessment.write: %d", w.Code)
	}
	if w := scheduleCall(h, a, http.MethodPut, "/compliance/assessment/schedule", `{"enabled":true,"frequency":"monthly"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown frequency: %d", w.Code)
	}
}

func TestAssessmentScheduleRoutesRefusalsAudited(t *testing.T) {
	h, _, _, _, _, _, _ := newComplianceHandler(t)
	rec := &routetest.Recorder{}
	r := route.New("compliance", rec, nil)
	h.assessmentScheduleRoutes(r)
	routetest.RefusalsAudited(t, r, rec)
}

// Each run happens on the saver's authority now: refused (and audited) when
// it is gone or unknown, nothing assessed; "run now" on a paused schedule is
// refused; saving again resumes it.
func TestAssessmentScheduleNeedsTheSaversAuthority(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		auth   scheduleAuthority
		reason string
		paused bool
	}{
		"revoked":   {scheduleAuthority{answer: authority.Answer{Active: true, Missing: []string{permAssessmentWrite}}}, authority.ReasonRevoked, true},
		"auth down": {scheduleAuthority{err: errors.New("unreachable")}, authority.ReasonUnknown, false},
		"holds it":  {scheduleAuthority{answer: authority.Answer{Active: true}}, "", false},
	} {
		t.Run(name, func(t *testing.T) {
			h, svc, keycore, _, _, _, _ := newComplianceHandler(t)
			keycore.keys["t1"] = []map[string]interface{}{{"id": "k1", "algorithm": "AES-256", "status": "active", "current_version": 1}}
			events := &runEvents{}
			svc.events, svc.authority = events, tc.auth
			admin := &pkgauth.Claims{UserID: "alice", TenantID: "t1", Permissions: []string{"*"}}
			if w := scheduleCall(h, admin, http.MethodPut, "/compliance/assessment/schedule", `{"enabled":true,"frequency":"daily"}`); w.Code != http.StatusOK {
				t.Fatalf("save: %d %s", w.Code, w.Body)
			}
			s, _ := svc.store.GetAssessmentSchedule(ctx, "t1")
			s.NextRunAt = time.Now().UTC().Add(-time.Minute)
			_ = svc.store.UpsertAssessmentSchedule(ctx, s)
			if err := svc.RunDueSchedules(ctx); err != nil {
				t.Fatal(err)
			}
			got, _ := svc.store.GetAssessmentSchedule(ctx, "t1")
			if len(events.data) != 1 {
				t.Fatalf("%d run events", len(events.data))
			}
			ev := events.data[0]
			if tc.reason == "" {
				if got.LastResult != "assessed" || got.LastAssessmentID == "" || ev["result"] != "success" || ev["assessment_id"] != got.LastAssessmentID {
					t.Fatalf("a held authority did not assess: %+v %v", got, ev)
				}
				return
			}
			if got.LastResult != "refused" || got.LastAssessmentID != "" || (got.PausedReason != "") != tc.paused {
				t.Fatalf("after refusal: %+v", got)
			}
			if ev["result"] != "refused" || ev["reason"] != tc.reason || ev["authorized_by"] != "alice" {
				t.Fatalf("refusal audited as %v", ev)
			}
			if tc.paused {
				if w := scheduleCall(h, admin, http.MethodPost, "/compliance/assessment/schedule/run", ``); w.Code != http.StatusConflict {
					t.Fatalf("run now on a paused schedule: %d", w.Code)
				}
				bob := &pkgauth.Claims{UserID: "bob", TenantID: "t1", Permissions: []string{"*"}}
				if w := scheduleCall(h, bob, http.MethodPut, "/compliance/assessment/schedule", `{"enabled":true,"frequency":"daily"}`); w.Code != http.StatusOK {
					t.Fatalf("resave: %d", w.Code)
				}
				if got, _ := svc.store.GetAssessmentSchedule(ctx, "t1"); got.AuthorizedBy != "bob" || got.PausedReason != "" {
					t.Fatalf("after resave: %+v", got)
				}
			}
		})
	}
}

// The template save named its tenant in the body without a check until
// 13.66.0-beta, as the schedule save did.
func TestComplianceTemplateIsTheCallersTenantOnly(t *testing.T) {
	h, svc, _, _, _, _, _ := newComplianceHandler(t)
	a := &pkgauth.Claims{UserID: "admin-a", TenantID: "tenant-a", Permissions: []string{"*"}}
	if w := scheduleCall(h, a, http.MethodPost, "/compliance/templates", `{"tenant_id":"tenant-b","name":"planted","enabled":true}`); w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant template: %d %s", w.Code, w.Body)
	}
	if items, _ := svc.store.ListComplianceTemplates(context.Background(), "tenant-b"); len(items) != 0 {
		t.Fatalf("tenant-b got %d templates from tenant-a", len(items))
	}
	if w := scheduleCall(h, a, http.MethodPost, "/compliance/templates", `{"tenant_id":"tenant-a","name":"mine","enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("own template: %d %s", w.Code, w.Body)
	}
}

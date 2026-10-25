package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/authority"
	"vecta-kms/pkg/route/routetest"
)

func integrityKey(t *testing.T, svc *Service, name, createdBy string) Key {
	t.Helper()
	k, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: name, Algorithm: "AES-256",
		KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: createdBy})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func integrityCall(t *testing.T, h http.Handler, claims *pkgauth.Claims, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path+"?tenant_id=t1", strings.NewReader(body))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

var integrityAdmin = &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}

// A scheduled check runs VerifyKeyIntegrity on the keys the saver can see:
// intact keys pass, corrupt material is a failure (audited as such), and a
// key held in an HSM is not assessed, never a failure.
func TestIntegrityScheduleChecksTheSaversKeys(t *testing.T) {
	h, svc, events := newActorTestHandler(t)
	ctx := context.Background()
	store := svc.store.(*SQLStore)
	good := integrityKey(t, svc, "pay-1", "bob")
	bad := integrityKey(t, svc, "pay-2", "bob")
	inHSM := integrityKey(t, svc, "pay-3", "bob")
	hidden := integrityKey(t, svc, "pay-4", "mallory")
	if _, err := store.db.SQL().ExecContext(ctx, `UPDATE key_versions SET encrypted_material = X'00010203040506070809' WHERE tenant_id='t1' AND key_id=$1`, bad.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().ExecContext(ctx, `UPDATE key_versions SET protection = 'hsm_resident', encrypted_material = X'', wrapped_dek = X'' WHERE tenant_id='t1' AND key_id=$1`, inHSM.ID); err != nil {
		t.Fatal(err)
	}

	rec := &routetest.Recorder{}
	router := h.integrityScheduleRouter(rec)
	// bob may verify but sees only the keys he created (no key.inventory.read).
	bob := &pkgauth.Claims{UserID: "bob", TenantID: "t1", Role: "operator", Permissions: []string{permIntegrityVerify}}
	w := integrityCall(t, router, bob, http.MethodPost, "/integrity/schedules", `{"name":"payments","target_filter":"pay-*","interval_hours":24}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var created struct {
		Schedule IntegritySchedule `json:"schedule"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created.Schedule.AuthorizedBy != "bob" || created.Schedule.NextRunAt == nil {
		t.Fatalf("created %+v", created.Schedule)
	}
	if ev := rec.Last(t); ev.Action != "integrity_schedule_created" || ev.Event.Result != "success" {
		t.Fatalf("create audited as %+v", ev)
	}

	sched := NewRotationScheduler(svc, nil, &stubAuthority{answer: authority.Answer{Active: true, Role: "operator", Missing: []string{permInventoryRead}}}, log.Default())
	runs := &routetest.Recorder{}
	sched.audit, sched.primary = runs, func(context.Context) bool { return true }
	h.scheduler = sched
	w = integrityCall(t, router, bob, http.MethodPost, "/integrity/schedules/"+created.Schedule.ID+"/run", ``)
	if w.Code != http.StatusOK {
		t.Fatalf("run: %d %s", w.Code, w.Body)
	}
	var ran struct {
		Schedule IntegritySchedule `json:"schedule"`
		Outcome  IntegrityOutcome  `json:"outcome"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ran)
	o := ran.Outcome
	if o.Checked != 3 || o.Verified != 1 || o.NotAssessed != 1 || o.FailedCount != 1 || len(o.Failed) != 1 || o.Failed[0] != bad.ID {
		t.Fatalf("outcome %+v (hidden key %s must not be checked)", o, hidden.ID)
	}
	if s := ran.Schedule; s.LastResult != "failed" || s.LastChecked != 3 || s.LastFailed != 1 || s.LastNotAssessed != 1 || s.LastRunAt == nil {
		t.Fatalf("recorded %+v", s)
	}
	if ev := runs.Last(t); ev.Action != "integrity_check_run" || ev.Event.Result != "failure" || ev.Event.Details["severity"] != "critical" || ev.Event.Details["triggered_by"] != "manual:bob" {
		t.Fatalf("run audited as %+v", ev)
	}
	// Each key's own event carries its real result.
	want := map[string]string{good.ID: "success", bad.ID: "failure", inHSM.ID: "refused"}
	events.mu.Lock()
	for _, e := range events.events {
		if e["_subject"] != "audit.key.integrity_verified" {
			continue
		}
		d, _ := e["details"].(map[string]any)
		if d == nil {
			d = e
		}
		id, _ := d["key_id"].(string)
		if r, ok := want[id]; ok && d["result"] == r {
			delete(want, id)
		}
	}
	events.mu.Unlock()
	if len(want) != 0 {
		t.Fatalf("integrity events missing or with the wrong result: %v", want)
	}
}

// The tick runs due schedules on the saver's authority: a revoked one pauses
// (audited as refused), and "run now" on a paused schedule is refused.
func TestIntegrityScheduleAuthority(t *testing.T) {
	h, svc := newHandlerForTest(t)
	ctx := context.Background()
	integrityKey(t, svc, "pay-1", "alice")
	rec := &routetest.Recorder{}
	router := h.integrityScheduleRouter(rec)
	w := integrityCall(t, router, integrityAdmin, http.MethodPost, "/integrity/schedules", `{"name":"all","target_filter":"*","interval_hours":1}`)
	var created struct {
		Schedule IntegritySchedule `json:"schedule"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	sch := created.Schedule
	past := time.Now().UTC().Add(-time.Minute)
	sch.NextRunAt = &past
	if err := svc.store.PutIntegritySchedule(ctx, sch); err != nil {
		t.Fatal(err)
	}

	sched := NewRotationScheduler(svc, nil, &stubAuthority{answer: authority.Answer{Active: false, Missing: []string{}}}, log.Default())
	runs := &routetest.Recorder{}
	sched.audit, sched.primary = runs, func(context.Context) bool { return true }
	h.scheduler = sched
	sched.Tick(ctx)
	got, _ := svc.store.GetIntegritySchedule(ctx, "t1", sch.ID)
	if got.PausedReason == "" || got.LastResult != "refused" || got.LastChecked != 0 {
		t.Fatalf("revoked authority: %+v", got)
	}
	if ev := runs.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != authority.ReasonRevoked {
		t.Fatalf("refusal audited as %+v", ev)
	}
	if due, _ := svc.store.ListDueIntegritySchedules(ctx, time.Now().UTC().Add(48*time.Hour), 10); len(due) != 0 {
		t.Fatal("a paused schedule is still due")
	}
	if w := integrityCall(t, router, integrityAdmin, http.MethodPost, "/integrity/schedules/"+sch.ID+"/run", ``); w.Code != http.StatusConflict {
		t.Fatalf("run now on a paused schedule: %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "schedule_paused" {
		t.Fatalf("paused run refusal audited as %+v", ev)
	}
	// Saving again makes the saver its authority and resumes it.
	carol := &pkgauth.Claims{UserID: "carol", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	if w := integrityCall(t, router, carol, http.MethodPatch, "/integrity/schedules/"+sch.ID, `{"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ = svc.store.GetIntegritySchedule(ctx, "t1", sch.ID)
	if got.AuthorizedBy != "carol" || got.PausedReason != "" {
		t.Fatalf("after save %+v", got)
	}
	// Bad input is refused and audited.
	for _, body := range []string{`{"name":"","target_filter":"*","interval_hours":1}`, `{"name":"x","target_filter":"","interval_hours":1}`, `{"name":"x","target_filter":"*","interval_hours":0}`} {
		if w := integrityCall(t, router, integrityAdmin, http.MethodPost, "/integrity/schedules", body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", body, w.Code)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != "invalid_schedule" {
			t.Fatalf("refusal audited as %+v", ev)
		}
	}
}

func TestIntegrityScheduleRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.integrityScheduleRouter(rec), rec)
}

// The "scheduled jobs" routes stored jobs nothing ever ran; they are gone
// (13.66.0-beta).
func TestScheduledJobRoutesAreRemoved(t *testing.T) {
	h, _ := newHandlerForTest(t)
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/scheduling/jobs"}, {http.MethodPost, "/scheduling/jobs"},
		{http.MethodPatch, "/scheduling/jobs/sj_1"}, {http.MethodDelete, "/scheduling/jobs/sj_1"},
	} {
		w := httptest.NewRecorder()
		serveAsAdmin(h, w, httptest.NewRequest(r.method, r.path+"?tenant_id=t1", strings.NewReader(`{}`)))
		if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s still answers: %d", r.method, r.path, w.Code)
		}
	}
}

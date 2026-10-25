package main

import (
	"context"
	"encoding/json"
	"errors"
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

func rotationCall(t *testing.T, h *Handler, claims *pkgauth.Claims, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if claims == nil {
		serveAsAdmin(h, rr, req)
	} else {
		h.ServeHTTP(rr, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
	}
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

func mustKey(t *testing.T, svc *Service, name string, tags ...string) Key {
	t.Helper()
	k, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: name, Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", Tags: tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyVersion(t *testing.T, svc *Service, id string) int {
	t.Helper()
	k, err := svc.store.GetKey(context.Background(), "t1", id)
	if err != nil {
		t.Fatal(err)
	}
	return k.CurrentVersion
}

// A trigger rotates exactly the active keys the filter selects, records one
// run per key with the real outcome, and audits the counts.
func TestRotationTriggerRotatesMatchingKeys(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	app1, app2, other := mustKey(t, svc, "app-1"), mustKey(t, svc, "app-2"), mustKey(t, svc, "db-1")

	rr, out := rotationCall(t, h, nil, http.MethodPost, "/rotation/policies",
		`{"name":"apps","target_filter":"app-*","interval_days":30}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	id := out["policy"].(map[string]any)["id"].(string)
	if e := rec.Last(t); e.Action != "rotation_policy_created" || e.Event.Result != "success" {
		t.Fatalf("create event %+v", e)
	}

	rr, out = rotationCall(t, h, nil, http.MethodPost, "/rotation/policies/"+id+"/trigger", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("trigger: %d %s", rr.Code, rr.Body)
	}
	outcome := out["outcome"].(map[string]any)
	if outcome["matched"] != float64(2) || outcome["rotated"] != float64(2) || outcome["failed"] != float64(0) {
		t.Fatalf("outcome %v", outcome)
	}
	if keyVersion(t, svc, app1.ID) != 2 || keyVersion(t, svc, app2.ID) != 2 || keyVersion(t, svc, other.ID) != 1 {
		t.Fatal("rotation did not follow the filter")
	}
	if e := rec.Last(t); e.Action != "rotation_policy_triggered" || e.Event.Result != "success" || e.Event.Details["rotated"] != 2 {
		t.Fatalf("trigger event %+v", e)
	}
	runs, _ := svc.store.ListRotationRuns(context.Background(), "t1", id)
	if len(runs) != 2 || runs[0].Status != "success" || runs[0].CompletedAt == nil {
		t.Fatalf("runs %+v", runs)
	}
	p, _ := svc.store.GetRotationPolicy(context.Background(), "t1", id)
	if p.TotalRotations != 2 || p.LastRotationAt == nil || p.Status != "active" {
		t.Fatalf("policy after run %+v", p)
	}
	for _, c := range []struct{ method, path, body, action string }{
		{http.MethodGet, "/rotation/policies", "", "rotation_policies_listed"},
		{http.MethodPatch, "/rotation/policies/" + id, `{"interval_days":60}`, "rotation_policy_updated"},
		{http.MethodGet, "/rotation/runs", "", "rotation_runs_listed"},
		{http.MethodGet, "/rotation/upcoming", "", "rotation_upcoming_listed"},
		{http.MethodDelete, "/rotation/policies/" + id, "", "rotation_policy_deleted"},
	} {
		if rr, _ := rotationCall(t, h, nil, c.method, c.path, c.body); rr.Code >= 300 {
			t.Fatalf("%s %s: %d %s", c.method, c.path, rr.Code, rr.Body)
		}
		if e := rec.Last(t); e.Action != c.action || e.Event.Result != "success" {
			t.Fatalf("%s %s audited as %+v", c.method, c.path, e)
		}
	}
}

// A caller without access to the keys gets failed runs with the refusal, and
// the policy is marked error: nothing is reported as rotated.
func TestRotationTriggerRecordsRefusals(t *testing.T) {
	h, svc := newHandlerForTest(t)
	k := mustKey(t, svc, "svc-key", "pci")
	_, out := rotationCall(t, h, nil, http.MethodPost, "/rotation/policies", `{"name":"pci","target_filter":"tag:pci","interval_days":90}`)
	id := out["policy"].(map[string]any)["id"].(string)

	bob := &pkgauth.Claims{UserID: "bob", TenantID: "t1", Role: "operator", Permissions: []string{"key.rotation.write"}}
	bob.Subject = "bob"
	rr, out := rotationCall(t, h, bob, http.MethodPost, "/rotation/policies/"+id+"/trigger", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("trigger: %d %s", rr.Code, rr.Body)
	}
	if o := out["outcome"].(map[string]any); o["rotated"] != float64(0) || o["failed"] != float64(1) {
		t.Fatalf("outcome %v", o)
	}
	if keyVersion(t, svc, k.ID) != 1 {
		t.Fatal("key rotated without access")
	}
	p, _ := svc.store.GetRotationPolicy(context.Background(), "t1", id)
	if p.Status != "error" || p.LastError == "" {
		t.Fatalf("policy %+v", p)
	}
}

// Only key policies with a valid filter are accepted; the dropped cron and
// notify fields are rejected rather than silently stored.
func TestRotationPolicyValidation(t *testing.T) {
	h, _ := newHandlerForTest(t)
	for _, body := range []string{
		`{"name":"s","target_type":"secret","target_filter":"*","interval_days":30}`,
		`{"name":"n","target_filter":"","interval_days":30}`,
		`{"name":"c","target_filter":"*","interval_days":30,"cron_expr":"0 0 * * *"}`,
		`{"name":"i","target_filter":"*","interval_days":0}`,
	} {
		if rr, _ := rotationCall(t, h, nil, http.MethodPost, "/rotation/policies", body); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", body, rr.Code)
		}
	}
}

// stubAuthority answers as auth would for a policy's authorizing person.
type stubAuthority struct {
	answer authority.Answer
	err    error
	asked  []string
}

func (a *stubAuthority) Authority(_ context.Context, tenantID, userID string, perms []string) (authority.Answer, error) {
	a.asked = append(a.asked, tenantID+"/"+userID+"/"+strings.Join(perms, ","))
	if a.err != nil {
		return authority.Answer{}, a.err
	}
	out := a.answer
	missing := []string{}
	for _, p := range perms {
		for _, m := range a.answer.Missing {
			if p == m {
				missing = append(missing, p)
			}
		}
	}
	out.Missing = missing
	return out, nil
}

var adminAuthority = authority.Answer{Active: true, Role: "admin", Missing: []string{}}

// The scheduler rotates due auto-rotate policies on the primary, as the
// person who saved the policy, and never runs on a cluster member.
func TestRotationSchedulerRunsDuePoliciesOnPrimaryOnly(t *testing.T) {
	_, svc := newHandlerForTest(t)
	k := mustKey(t, svc, "nightly-1")
	due := time.Now().UTC().Add(-time.Minute)
	if _, err := svc.store.CreateRotationPolicy(context.Background(), RotationPolicy{
		ID: "rp-due", TenantID: "t1", Name: "nightly", TargetType: "key", TargetFilter: "nightly-*",
		IntervalDays: 1, AutoRotate: true, Enabled: true, Status: "active", NextRotationAt: &due, AuthorizedBy: "alice",
	}); err != nil {
		t.Fatal(err)
	}
	sched := NewRotationScheduler(svc, nil, &stubAuthority{answer: adminAuthority}, log.Default())
	audit := &routetest.Recorder{}
	sched.audit = audit
	sched.primary = func(context.Context) bool { return false }
	sched.Tick(context.Background())
	if keyVersion(t, svc, k.ID) != 1 || len(audit.Events()) != 0 {
		t.Fatal("member ran the rotation scheduler")
	}
	sched.primary = func(context.Context) bool { return true }
	sched.Tick(context.Background())
	if keyVersion(t, svc, k.ID) != 2 {
		t.Fatal("due policy was not rotated")
	}
	// The run is audited with the counts of what it actually rotated.
	if ev := audit.Events(); len(ev) != 1 || ev[0].Action != "rotation_policy_run" || ev[0].Event.Result != "success" ||
		ev[0].Event.TargetID != "rp-due" || ev[0].Event.Details["rotated"] != 1 || ev[0].Event.Details["matched"] != 1 {
		t.Fatalf("scheduled run audit: %+v", ev)
	}
	p, _ := svc.store.GetRotationPolicy(context.Background(), "t1", "rp-due")
	if p.NextRotationAt == nil || !p.NextRotationAt.After(time.Now().UTC()) {
		t.Fatalf("next rotation not advanced: %+v", p.NextRotationAt)
	}
	runs, _ := svc.store.ListRotationRuns(context.Background(), "t1", "rp-due")
	if len(runs) != 1 || runs[0].TriggeredBy != "schedule:alice" || runs[0].Status != "success" {
		t.Fatalf("runs %+v", runs)
	}
	sched.Tick(context.Background()) // no longer due
	if keyVersion(t, svc, k.ID) != 2 || len(audit.Events()) != 1 {
		t.Fatal("policy ran again before it was due")
	}
}

func TestRotationRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.rotationRouter(rec), rec)
}

// A scheduled run acts only on the authority of the person who saved the
// policy, asked of auth at the moment it runs (13.66.0-beta).
func TestScheduledRotationNeedsTheSaversAuthorityNow(t *testing.T) {
	ctx := context.Background()
	due := time.Now().UTC().Add(-time.Minute)
	policy := func(t *testing.T, svc *Service, by string) {
		t.Helper()
		if _, err := svc.store.CreateRotationPolicy(ctx, RotationPolicy{
			ID: "rp-1", TenantID: "t1", Name: "nightly", TargetType: "key", TargetFilter: "nightly-*",
			IntervalDays: 1, AutoRotate: true, Enabled: true, Status: "active", NextRotationAt: &due, AuthorizedBy: by,
		}); err != nil {
			t.Fatal(err)
		}
	}
	run := func(t *testing.T, svc *Service, auth authority.Checker) (*routetest.Recorder, RotationPolicy) {
		t.Helper()
		sched := NewRotationScheduler(svc, nil, auth, log.Default())
		rec := &routetest.Recorder{}
		sched.audit, sched.primary = rec, func(context.Context) bool { return true }
		sched.Tick(ctx)
		p, err := svc.store.GetRotationPolicy(ctx, "t1", "rp-1")
		if err != nil {
			t.Fatal(err)
		}
		return rec, p
	}

	t.Run("revoked: paused, refused, nothing rotated, not due again", func(t *testing.T) {
		_, svc := newHandlerForTest(t)
		k := mustKey(t, svc, "nightly-1")
		policy(t, svc, "alice")
		auth := &stubAuthority{answer: authority.Answer{Active: true, Missing: []string{"key.rotate"}}}
		rec, p := run(t, svc, auth)
		if keyVersion(t, svc, k.ID) != 1 || p.PausedReason == "" || !strings.Contains(p.PausedReason, "key.rotate") {
			t.Fatalf("revoked authority ran or did not pause: v%d %+v", keyVersion(t, svc, k.ID), p)
		}
		if ev := rec.Last(t); ev.Action != "rotation_policy_run" || ev.Event.Result != "refused" || ev.Event.Details["reason"] != authority.ReasonRevoked || ev.Event.Details["authorized_by"] != "alice" {
			t.Fatalf("refusal audited as %+v", ev)
		}
		if len(auth.asked) != 1 || auth.asked[0] != "t1/alice/key.rotation.write,key.rotate" {
			t.Fatalf("asked %v", auth.asked)
		}
		if due, _ := svc.store.ListDueRotationPolicies(ctx, time.Now().UTC().Add(time.Hour), 10); len(due) != 0 {
			t.Fatal("a paused policy is still due")
		}
	})

	t.Run("no one on record: paused", func(t *testing.T) {
		_, svc := newHandlerForTest(t)
		k := mustKey(t, svc, "nightly-1")
		policy(t, svc, "")
		auth := &stubAuthority{answer: adminAuthority}
		rec, p := run(t, svc, auth)
		if keyVersion(t, svc, k.ID) != 1 || p.PausedReason == "" || len(auth.asked) != 0 {
			t.Fatalf("a policy with no authorizer ran: %+v asked %v", p, auth.asked)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != authority.ReasonRevoked {
			t.Fatalf("refusal audited as %+v", ev)
		}
	})

	t.Run("auth unreachable: postponed, not paused", func(t *testing.T) {
		_, svc := newHandlerForTest(t)
		k := mustKey(t, svc, "nightly-1")
		policy(t, svc, "alice")
		rec, p := run(t, svc, &stubAuthority{err: errors.New("auth unreachable")})
		if keyVersion(t, svc, k.ID) != 1 || p.PausedReason != "" || p.NextRotationAt == nil || !p.NextRotationAt.After(time.Now().UTC()) {
			t.Fatalf("unknown authority: v%d %+v", keyVersion(t, svc, k.ID), p)
		}
		if ev := rec.Last(t); ev.Event.Result != "refused" || ev.Event.Details["reason"] != authority.ReasonUnknown {
			t.Fatalf("refusal audited as %+v", ev)
		}
	})

	t.Run("a person without access to the key: that rotation fails, the run is not a success", func(t *testing.T) {
		_, svc := newHandlerForTest(t)
		k := mustKey(t, svc, "nightly-1")
		policy(t, svc, "bob")
		bob := &stubAuthority{answer: authority.Answer{Active: true, Role: "operator", Missing: []string{permAccessAdmin}}}
		rec, p := run(t, svc, bob)
		if keyVersion(t, svc, k.ID) != 1 || p.Status != "error" {
			t.Fatalf("bob rotated a key he has no grant on: v%d %+v", keyVersion(t, svc, k.ID), p)
		}
		if ev := rec.Last(t); ev.Event.Result != "failure" || ev.Event.Details["failed"] != 1 {
			t.Fatalf("run audited as %+v", ev)
		}
	})

	t.Run("saving the policy again makes the saver its authority and resumes it", func(t *testing.T) {
		h, svc := newHandlerForTest(t)
		mustKey(t, svc, "nightly-1")
		policy(t, svc, "alice")
		if err := svc.store.HoldRotationPolicy(ctx, "t1", "rp-1", due, "alice no longer holds key.rotate"); err != nil {
			t.Fatal(err)
		}
		carol := &pkgauth.Claims{UserID: "carol", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
		if rr, _ := rotationCall(t, h, carol, http.MethodPatch, "/rotation/policies/rp-1?tenant_id=t1", `{"enabled":true}`); rr.Code != http.StatusOK {
			t.Fatalf("save: %d %s", rr.Code, rr.Body)
		}
		p, _ := svc.store.GetRotationPolicy(ctx, "t1", "rp-1")
		if p.AuthorizedBy != "carol" || p.PausedReason != "" {
			t.Fatalf("after save: %+v", p)
		}
	})
}

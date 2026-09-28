package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"vecta-kms/pkg/route"
)

func auditEvent(id, action, actor string, at time.Time) map[string]interface{} {
	return map[string]interface{}{"id": id, "action": action, "actor_id": actor, "timestamp": at.UTC().Format(time.RFC3339Nano)}
}

// A rule the engine can't run is reported invalid, with the reason, before
// anyone saves it.
func TestCheckRuleValidation(t *testing.T) {
	svc, _, _, _, _, _ := newReportingService(t)
	for _, rule := range []AlertRule{
		{Condition: "expression", Expression: `action ==`},
		{Condition: "expression"},
		{Condition: "threshold", Threshold: 3},
		{Condition: "cel"},
	} {
		if res := svc.CheckRule(context.Background(), "t1", RuleCheckInput{Rule: rule, ReplayHours: -1}); res.Valid || res.Error == "" {
			t.Fatalf("%+v accepted: %+v", rule, res)
		}
	}
}

// The replay runs the live matcher over the tenant's real audit events: a
// threshold rule fires once the matches in its window reach the threshold,
// events outside the replay window are ignored, and nothing is stored.
func TestCheckRuleReplaysRecentAuditEvents(t *testing.T) {
	svc, store, audit, _, _, _ := newReportingService(t)
	now := time.Now().UTC()
	audit.events["t1"] = []map[string]interface{}{
		auditEvent("e0", "audit.auth.login_failed", "mallory", now.Add(-30*time.Hour)), // outside 24h
		auditEvent("e1", "audit.auth.login_failed", "mallory", now.Add(-10*time.Minute)),
		auditEvent("e2", "audit.key.rotate", "alice", now.Add(-9*time.Minute)),
		auditEvent("e3", "audit.auth.login_failed", "mallory", now.Add(-9*time.Minute)),
		auditEvent("e4", "audit.auth.login_failed", "mallory", now.Add(-8*time.Minute)),
		auditEvent("e5", "audit.auth.login_failed", "mallory", now.Add(-7*time.Minute)),
		auditEvent("e6", "audit.auth.login_failed", "mallory", now.Add(-1*time.Minute)), // new window: 1 match
	}
	rule := AlertRule{Name: "brute force", Condition: "threshold", EventPattern: "audit.auth.login_failed", Threshold: 3, WindowSecond: 300}
	res := svc.CheckRule(context.Background(), "t1", RuleCheckInput{Rule: rule})
	if !res.Valid || res.Replay == nil || res.ReplayError != "" {
		t.Fatalf("check %+v", res)
	}
	r := res.Replay
	if r.Hours != 24 || r.EventsScanned != 6 || r.Matched != 5 || r.Fired != 2 || r.Truncated {
		t.Fatalf("replay %+v", r)
	}
	if len(r.Samples) != 2 || r.Samples[0].EventID != "e4" || r.Samples[1].EventID != "e5" || r.Samples[0].ActorID != "mallory" {
		t.Fatalf("samples %+v", r.Samples)
	}
	if rules, _ := store.ListRules(context.Background(), "t1"); len(rules) != 0 {
		t.Fatal("checking a rule stored it")
	}
	if alerts, _ := store.ListAlerts(context.Background(), "t1", AlertQuery{Limit: 10}); len(alerts) != 0 {
		t.Fatal("checking a rule raised alerts")
	}
}

// A supplied event gets the live decision; an expression rule matches on
// the same fields live alerting passes it.
func TestCheckRuleDecidesSuppliedEvent(t *testing.T) {
	svc, _, _, _, _, _ := newReportingService(t)
	rule := AlertRule{Condition: "expression", Expression: `action == "audit.key.export" AND actor_id != "backup-svc"`}
	hit := svc.CheckRule(context.Background(), "t1", RuleCheckInput{Rule: rule, ReplayHours: -1,
		Event: map[string]interface{}{"action": "audit.key.export", "actor_id": "mallory"}})
	if hit.Event == nil || !hit.Event.Matched || !hit.Event.FiresNow || hit.Replay != nil {
		t.Fatalf("hit %+v", hit)
	}
	miss := svc.CheckRule(context.Background(), "t1", RuleCheckInput{Rule: rule, ReplayHours: -1,
		Event: map[string]interface{}{"action": "audit.key.export", "actor_id": "backup-svc"}})
	if miss.Event == nil || miss.Event.Matched || miss.Event.FiresNow {
		t.Fatalf("miss %+v", miss)
	}
	// A threshold rule on a first event: matched, but not enough yet.
	th := svc.CheckRule(context.Background(), "t1", RuleCheckInput{ReplayHours: -1,
		Rule:  AlertRule{Condition: "threshold", EventPattern: "audit.auth.*", Threshold: 5, WindowSecond: 60},
		Event: map[string]interface{}{"action": "audit.auth.login_failed"}})
	if th.Event == nil || !th.Event.Matched || th.Event.FiresNow || th.Event.InWindow != 0 {
		t.Fatalf("threshold %+v", th.Event)
	}
}

// With no audit service there is no replay result, only the reason.
func TestCheckRuleReplayUnavailable(t *testing.T) {
	svc, _, _, _, _, _ := newReportingService(t)
	svc.audit = nil
	res := svc.CheckRule(context.Background(), "t1", RuleCheckInput{Rule: AlertRule{Condition: "threshold", EventPattern: "*"}})
	if !res.Valid || res.Replay != nil || res.ReplayError == "" {
		t.Fatalf("check %+v", res)
	}
}

// The route is audited as rule_tested with the outcome in its details.
func TestRuleTestRouteAudited(t *testing.T) {
	h, _, rec := newAuditedReportingHandler(t)
	body := `{"rule":{"condition":"threshold","event_pattern":"audit.key.*"},"replay_hours":1}`
	rr := serve(h, adminOf("t1"), http.MethodPost, "/alerts/rules/test?tenant_id=t1", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("test route: %d %s", rr.Code, rr.Body)
	}
	var out struct {
		Result RuleCheck `json:"result"`
	}
	if json.Unmarshal(rr.Body.Bytes(), &out) != nil || !out.Result.Valid || out.Result.Replay == nil || out.Result.Replay.Hours != 1 {
		t.Fatalf("result %s", rr.Body)
	}
	evs := rec.Events()
	last := evs[len(evs)-1]
	if last.Action != "rule_tested" || last.Event.Result != route.ResultSuccess || last.Event.Details["valid"] != true {
		t.Fatalf("audit %+v", last)
	}
}

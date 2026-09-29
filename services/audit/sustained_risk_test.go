package main

import (
	"context"
	"testing"
	"time"
)

// Three high-risk events on one key within the window publish
// audit.security.sustained_risk_detected once, on the stream (so playbooks
// see it), naming the key as its target. Two don't, and nothing is
// published under the old auto_quarantined name, which claimed a quarantine
// that never happened.
func TestSustainedRiskPublishedOnceWithTarget(t *testing.T) {
	_, svc, store, _ := newAuditHandler(t, false, false)
	stream := &loopbackPublisher{svc: svc}
	svc.publisher = stream
	svc.SetRiskDetector(NewSustainedRiskDetector(stream))
	ctx := context.Background()
	send := func() {
		t.Helper()
		if _, err := svc.ProcessEvent(ctx, AuditEvent{
			TenantID: "t1", Timestamp: time.Now().UTC(), Service: "keycore", Action: "audit.key.access_refused",
			ActorID: "u1", ActorType: "human", Result: "refused", TargetType: "key", TargetID: "k1", RiskScore: 90,
		}); err != nil {
			t.Fatal(err)
		}
	}
	send()
	send()
	if len(stream.subjects) != 0 {
		t.Fatalf("fired below the sustained threshold: %v", stream.subjects)
	}
	send()
	send()
	if len(stream.subjects) != 1 || stream.subjects[0] != sustainedRiskSubject {
		t.Fatalf("published %v, want one %s", stream.subjects, sustainedRiskSubject)
	}
	got, err := store.QueryEvents(ctx, "t1", EventQuery{Action: sustainedRiskSubject, Limit: 5})
	if err != nil || len(got) != 1 {
		t.Fatalf("recorded %d, err %v", len(got), err)
	}
	if got[0].TargetType != "key" || got[0].TargetID != "k1" || got[0].Result != "warning" {
		t.Fatalf("recorded %+v", got[0])
	}
	if old, _ := store.QueryEvents(ctx, "t1", EventQuery{Action: "audit.security.auto_quarantined", Limit: 5}); len(old) != 0 {
		t.Fatalf("auto_quarantined still recorded: %+v", old)
	}
}

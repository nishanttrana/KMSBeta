package main

import (
	"context"
	"testing"
	"time"
)

// seedUsage inserts a usage event at a specific time for detection tests.
func seedUsage(t *testing.T, s *Service, tenantID, keyID, actorID string, at time.Time) {
	t.Helper()
	if err := s.store.InsertKeyUsageEvent(context.Background(), KeyUsageEvent{
		ID:         newID("kue"),
		TenantID:   tenantID,
		KeyID:      keyID,
		Operation:  "encrypt",
		ActorID:    actorID,
		OccurredAt: at,
	}); err != nil {
		t.Fatalf("seed usage: %v", err)
	}
}

// forceSweep clears the per-tenant rate-limit gate so a sweep runs now.
func forceSweep(s *Service, tenantID string) {
	threatSweepLast.Delete(tenantID)
	s.sweepThreatSignals(context.Background(), tenantID)
}

func signalsByType(t *testing.T, s *Service, tenantID string) map[string]ThreatSignal {
	t.Helper()
	sigs, err := s.store.ListThreatSignals(context.Background(), tenantID, 200)
	if err != nil {
		t.Fatalf("list signals: %v", err)
	}
	out := map[string]ThreatSignal{}
	for _, sig := range sigs {
		out[sig.SignalType] = sig
	}
	return out
}

func TestThreatDetectsNewActor(t *testing.T) {
	_, svc := newHandlerForTest(t)
	now := time.Now().UTC()
	// Established history for known actor over the last hours.
	for i := 0; i < newActorHistoryMin+2; i++ {
		seedUsage(t, svc, "t1", "key-A", "alice", now.Add(-time.Duration(i+1)*time.Minute))
	}
	// A brand-new actor touches the same key.
	seedUsage(t, svc, "t1", "key-A", "mallory", now.Add(-30*time.Second))

	forceSweep(svc, "t1")

	got := signalsByType(t, svc, "t1")
	sig, ok := got["new_actor"]
	if !ok {
		t.Fatalf("expected new_actor signal, got %+v", got)
	}
	if sig.ActorID != "mallory" || sig.KeyID != "key-A" || sig.Severity != "high" {
		t.Fatalf("unexpected signal: %+v", sig)
	}
}

func TestThreatNoNewActorSignalForKnownActor(t *testing.T) {
	_, svc := newHandlerForTest(t)
	now := time.Now().UTC()
	for i := 0; i < newActorHistoryMin+5; i++ {
		seedUsage(t, svc, "t1", "key-A", "alice", now.Add(-time.Duration(i+1)*time.Minute))
	}
	forceSweep(svc, "t1")
	if _, ok := signalsByType(t, svc, "t1")["new_actor"]; ok {
		t.Fatal("did not expect new_actor signal when only known actor is active")
	}
}

func TestThreatDetectsVolumeSpike(t *testing.T) {
	_, svc := newHandlerForTest(t)
	now := time.Now().UTC()
	// Modest baseline: a few ops/day spread across the prior week.
	for d := 1; d <= 6; d++ {
		base := now.Add(-time.Duration(d) * 24 * time.Hour)
		for i := 0; i < 3; i++ {
			seedUsage(t, svc, "t1", "key-B", "svc", base.Add(time.Duration(i)*time.Minute))
		}
	}
	// Spike: far above 4x the hourly baseline in the last hour.
	for i := 0; i < volumeSpikeMinOps+40; i++ {
		seedUsage(t, svc, "t1", "key-B", "svc", now.Add(-time.Duration(i)*time.Second))
	}

	forceSweep(svc, "t1")

	sig, ok := signalsByType(t, svc, "t1")["volume_spike"]
	if !ok {
		t.Fatal("expected volume_spike signal")
	}
	if sig.KeyID != "key-B" {
		t.Fatalf("unexpected volume_spike key: %+v", sig)
	}
}

func TestThreatDetectsDormantActivity(t *testing.T) {
	_, svc := newHandlerForTest(t)
	now := time.Now().UTC()
	// One use well beyond the dormant threshold, before the sweep window.
	seedUsage(t, svc, "t1", "key-C", "svc", now.Add(-dormantThreshold-threatSweepWindow-48*time.Hour))
	// Fresh activity inside the sweep window.
	seedUsage(t, svc, "t1", "key-C", "svc", now.Add(-2*time.Minute))

	forceSweep(svc, "t1")

	sig, ok := signalsByType(t, svc, "t1")["dormant_key_activity"]
	if !ok {
		t.Fatal("expected dormant_key_activity signal")
	}
	if sig.Severity != "medium" {
		t.Fatalf("unexpected dormant severity: %+v", sig)
	}
}

func TestThreatSignalDedupe(t *testing.T) {
	_, svc := newHandlerForTest(t)
	now := time.Now().UTC()
	for i := 0; i < newActorHistoryMin+2; i++ {
		seedUsage(t, svc, "t1", "key-A", "alice", now.Add(-time.Duration(i+1)*time.Minute))
	}
	seedUsage(t, svc, "t1", "key-A", "mallory", now.Add(-30*time.Second))

	forceSweep(svc, "t1")
	forceSweep(svc, "t1") // second sweep same day must not duplicate

	sigs, err := svc.store.ListThreatSignals(context.Background(), "t1", 200)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, s := range sigs {
		if s.SignalType == "new_actor" && s.ActorID == "mallory" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one deduped new_actor signal, got %d", count)
	}
}

func TestThreatAckSignal(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ok, err := svc.store.CreateThreatSignal(context.Background(), ThreatSignal{
		ID:          newID("tsig"),
		TenantID:    "t1",
		SignalType:  "new_actor",
		KeyID:       "key-A",
		ActorID:     "mallory",
		Severity:    "high",
		Description: "test",
		DedupeKey:   "new_actor|key-A|mallory|today",
		DetectedAt:  time.Now().UTC(),
	})
	if err != nil || !ok {
		t.Fatalf("create signal ok=%v err=%v", ok, err)
	}
	sigs, _ := svc.store.ListThreatSignals(context.Background(), "t1", 10)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if err := svc.store.AckThreatSignal(context.Background(), "t1", sigs[0].ID, "responder"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	// Second ack must fail (already acknowledged).
	if err := svc.store.AckThreatSignal(context.Background(), "t1", sigs[0].ID, "responder"); err == nil {
		t.Fatal("expected error acking an already-acknowledged signal")
	}
	sigs, _ = svc.store.ListThreatSignals(context.Background(), "t1", 10)
	if sigs[0].AcknowledgedAt == nil || sigs[0].AcknowledgedBy != "responder" {
		t.Fatalf("ack not persisted: %+v", sigs[0])
	}
}

func TestCanaryProbeThroughKeyAPITrips(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := contextWithAccessActor(context.Background(), AccessActor{
		UserID: "mallory", Authenticated: true, SourceIP: "10.0.0.9",
	})
	if err := svc.store.CreateCanaryKey(ctx, CanaryKey{
		ID: "decoy-1", TenantID: "t1", Name: "prod-master-decoy",
		Algorithm: "AES-256-GCM", Purpose: "detect_exfiltration", Active: true,
	}); err != nil {
		t.Fatalf("create canary: %v", err)
	}
	// Probing the canary through the real key API must return not-found...
	if _, err := svc.GetKey(ctx, "t1", "decoy-1"); err == nil {
		t.Fatal("expected not-found when resolving a canary key id")
	}
	// ...and must raise a critical canary_tripped signal and record the trip.
	sig, ok := signalsByType(t, svc, "t1")["canary_tripped"]
	if !ok {
		t.Fatal("expected canary_tripped signal")
	}
	if sig.Severity != "critical" || sig.ActorID != "mallory" {
		t.Fatalf("unexpected canary signal: %+v", sig)
	}
	trips, err := svc.store.ListCanaryTrips(ctx, "t1", "decoy-1", 10)
	if err != nil {
		t.Fatalf("list trips: %v", err)
	}
	if len(trips) != 1 {
		t.Fatalf("expected 1 recorded trip, got %d", len(trips))
	}
}

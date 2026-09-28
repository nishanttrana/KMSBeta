package main

import (
	"context"
	"testing"
	"time"
)

// Milestones come from pkg/cryptocatalog and cite their source. Before
// 3.2.0-beta the timeline showed "CNSA 2.0 hybrid by 2028" and an "EU
// crypto-agility baseline 2029-06-30" that no document sets, with a status
// derived from a readiness score.
func TestTimelineMilestonesAreSourced(t *testing.T) {
	svc, _, _, _ := newPQCService(t)
	svc.now = func() time.Time { return time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC) }
	ms := svc.buildTimelineMilestones(map[string]int{"RSA-2048": 2, "ECDSA-P384": 1, "ML-DSA-65": 4, "RSA": 1})
	if len(ms) != 2 {
		t.Fatalf("milestones = %+v", ms)
	}
	if m := ms[0]; m.DueDate.Format("2006-01-02") != "2031-01-01" || m.AffectedAssets != 2 || m.Citation != "SP 800-131Ar3 ipd, Tables 3 and 6" || m.Description != "RSA-2048" {
		t.Fatalf("112-bit deprecation milestone = %+v", m)
	}
	if m := ms[1]; m.DueDate.Format("2006-01-02") != "2036-01-01" || m.AffectedAssets != 3 || m.Standard != "IR8547" || m.Status != "upcoming" {
		t.Fatalf("quantum disallowance milestone = %+v", m)
	}
	for _, m := range ms {
		if m.Standard == "cnsa2" || m.Standard == "eu-pqc" {
			t.Fatalf("unsourced milestone %+v", m)
		}
	}
}

func TestPlanDeadlineMustBeSourced(t *testing.T) {
	svc, _, _, _ := newPQCService(t)
	ctx := context.Background()
	if _, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: "t1", TimelineStandard: "cnsa2"}); err == nil {
		t.Fatal("a plan against an unsourced timeline got a made-up deadline")
	}
	plan, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.TimelineStandard != "nist-ir-8547-ipd" || plan.Deadline.Format("2006-01-02") != "2035-12-31" {
		t.Fatalf("default plan timeline %s %s", plan.TimelineStandard, plan.Deadline)
	}
	if plan, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: "t1", TimelineStandard: "cnsa2", Deadline: "2030-12-31"}); err != nil || plan.Deadline.Year() != 2030 {
		t.Fatalf("explicit deadline refused: %v %+v", err, plan.Deadline)
	}
}

func TestMigrationTargetsFollowTheCatalogue(t *testing.T) {
	for _, c := range []struct{ alg, asset, want string }{
		{"SLH-DSA-SHA2-128s", "key", "SLH-DSA-SHA2-128s"}, // was sent to ML-KEM-768
		{"ML-DSA-65", "key", "ML-DSA-65"},
		{"RSA-4096", "key", "ML-DSA-65"},
		{"ECDSA-P256", "certificate", "ML-DSA-65"},
		{"ECDH-P384", "key", "ML-KEM-768"},
		{"3DES", "key", "AES-256"},
		{"AES-128", "key", "AES-128"}, // acceptable, category 1: no change
		{"ECDH-P256", "tls_endpoint", "X25519MLKEM768"},
		{"RSA", "key", ""}, // not assessed: no target
	} {
		if got := migrationTarget(c.alg, c.asset); got != c.want {
			t.Errorf("migrationTarget(%s, %s) = %q, want %q", c.alg, c.asset, got, c.want)
		}
	}
	if got := migrationPhase("3DES", "AES-256"); got != "classical_replacement" {
		t.Errorf("symmetric replacement labelled %s", got)
	}
}

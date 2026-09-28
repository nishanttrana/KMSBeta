package main

import (
	"context"
	"testing"
	"time"
)

// The timeline is the customer's own plan deadlines; the product supplies
// none. A plan without a deadline has none (before 5.1.0-beta it defaulted
// to a standards date).
func TestTimelineIsTheCustomersPlanDeadlines(t *testing.T) {
	svc, _, _, _ := newPQCService(t)
	svc.now = func() time.Time { return time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC) }
	ctx := context.Background()
	if _, err := svc.StartReadinessScan(ctx, ScanRequest{TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	undated, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: "t1", Name: "no date"})
	if err != nil || !undated.Deadline.IsZero() || undated.TimelineStandard != "customer" {
		t.Fatalf("undated plan: %v %+v", err, undated)
	}
	if ms := svc.buildTimelineMilestones(ctx, "t1"); len(ms) != 0 {
		t.Fatalf("an undated plan produced milestones: %+v", ms)
	}
	dated, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: "t1", Name: "RSA out", Deadline: "2027-06-30", TimelineStandard: "board-policy-2026"})
	if err != nil {
		t.Fatal(err)
	}
	ms := svc.buildTimelineMilestones(ctx, "t1")
	if len(ms) != 1 || ms[0].ID != dated.ID || ms[0].Title != "RSA out" || ms[0].Standard != "board-policy-2026" ||
		ms[0].DueDate.Format("2006-01-02") != "2027-06-30" || ms[0].Status != "due_within_year" || ms[0].AffectedAssets != len(dated.Steps) {
		t.Fatalf("milestones = %+v", ms)
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
		{"AES-128", "key", "AES-128"},
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

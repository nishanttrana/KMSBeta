package main

import (
	"context"
	"testing"
	"time"
)

func keyOpEvent(tenant, op, result string, ms float64) AuditEvent {
	return AuditEvent{
		TenantID: tenant, Service: "keycore", Action: "audit.key." + op,
		ActorID: "u1", ActorType: "user", TargetType: "key", TargetID: "k1",
		Result: result, DurationMS: ms, Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{"key_id": "k1"},
	}
}

// Operations metrics come only from key-operation events that went through
// ingest: counts, errors (refusals and failures), measured latency and
// histogram percentiles. Other events and pending approvals don't count.
func TestOpsMetricsBuiltFromIngestedKeyOpEvents(t *testing.T) {
	_, svc, store, _ := newAuditHandler(t, false, false)
	ctx := context.Background()
	events := []AuditEvent{
		keyOpEvent("t1", "encrypt", "success", 0.2),
		keyOpEvent("t1", "encrypt", "success", 0.4),
		keyOpEvent("t1", "encrypt", "refused", 0.05),
		keyOpEvent("t1", "wrap", "failure", 3),
		keyOpEvent("t1", "encrypt", "pending_approval", 0.1), // never ran
		keyOpEvent("t2", "sign", "success", 1),               // other tenant
		{TenantID: "t1", Service: "auth", Action: "audit.auth.login", ActorID: "u1", Result: "success", Timestamp: time.Now().UTC()},
		{TenantID: "t1", Service: "other", Action: "audit.key.encrypt", ActorID: "u1", Result: "success", Timestamp: time.Now().UTC()},
	}
	for _, e := range events {
		if _, _, err := svc.ProcessEvent(ctx, e); err != nil {
			t.Fatalf("ingest %s: %v", e.Action, err)
		}
	}

	ov, err := store.GetOpsOverview(ctx, "t1", "24h")
	if err != nil {
		t.Fatal(err)
	}
	if ov.TotalOps != 4 || ov.TotalErrors != 2 {
		t.Fatalf("overview = %+v, want 4 ops / 2 errors", ov)
	}
	if got, want := ov.AvgLatencyMs, (0.2+0.4+0.05+3)/4; got < want-0.001 || got > want+0.001 {
		t.Fatalf("avg latency %.4f, want %.4f (sub-ms latency must not round to 0)", got, want)
	}

	lat, err := store.GetLatencyPercentiles(ctx, "t1", "24h")
	if err != nil {
		t.Fatal(err)
	}
	byOp := map[string]LatencyPercentiles{}
	for _, l := range lat {
		byOp[l.OpType] = l
	}
	enc := byOp["encrypt"]
	if enc.SampleOps != 3 || enc.P50Ms == nil || *enc.P50Ms != 0.25 || enc.P99Ms == nil || *enc.P99Ms != 0.5 {
		t.Fatalf("encrypt percentiles = %+v", enc)
	}
	if w := byOp["wrap"]; w.SampleOps != 1 || w.P50Ms == nil || *w.P50Ms != 5 {
		t.Fatalf("wrap percentiles = %+v", w)
	}

	errs, err := store.GetErrorBreakdown(ctx, "t1", "24h")
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 2 {
		t.Fatalf("error breakdown = %+v, want encrypt and wrap", errs)
	}
}

func TestBucketPercentileOverflowIsNotAnswered(t *testing.T) {
	counts := make([]int64, len(latencyBucketsMs)+1)
	counts[len(latencyBucketsMs)] = 10 // every sample slower than the last bound
	if p := bucketPercentile(counts, 10, 0.5); p != nil {
		t.Fatalf("overflow p50 = %v, want nil (unbounded)", *p)
	}
	if latencyBucket(1500*time.Microsecond) != 4 || latencyBucket(2*time.Second) != len(latencyBucketsMs) {
		t.Fatal("bucket boundaries")
	}
}

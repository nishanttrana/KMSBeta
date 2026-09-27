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
		Details: map[string]interface{}{"key_id": "k1", "metered_op": op},
	}
}

// Operations metrics come only from metered-operation events that went
// through ingest: counts, errors (refusals and failures), measured latency and
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
		// Not marked as a metered operation: never counted.
		{TenantID: "t1", Service: "keycore", Action: "audit.key.encrypt", ActorID: "u1", Result: "success", Timestamp: time.Now().UTC()},
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

// Any service's event marked metered_op is counted. A legacy publisher
// nests result and duration_ms under "data"; ingest reads them from there.
func TestOpsMetricsCountAnyServicesMeteredEvents(t *testing.T) {
	_, svc, store, _ := newAuditHandler(t, false, false)
	ctx := context.Background()
	for _, raw := range []string{
		`{"tenant_id":"t1","service":"dataprotect","action":"audit.dataprotect.tokenized","data":{"metered_op":"tokenize","duration_ms":0.3,"count":25}}`,
		`{"tenant_id":"t1","service":"dataprotect","action":"audit.dataprotect.tokenize_refused","data":{"metered_op":"tokenize","duration_ms":0.1,"result":"refused","reason":"permission_denied"}}`,
		`{"tenant_id":"t1","service":"dataprotect","action":"audit.dataprotect.tokenized","data":{"metered_op":"Bad Name","duration_ms":1}}`,
	} {
		ev, err := parseIncomingEvent("audit.dataprotect.x", []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := svc.ProcessEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := store.GetServiceStats(ctx, "t1", "24h")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Service != "dataprotect" || stats[0].TotalOps != 2 || stats[0].TotalErrors != 1 {
		t.Fatalf("service stats = %+v", stats)
	}
	ov, err := store.GetOpsOverview(ctx, "t1", "24h")
	if err != nil {
		t.Fatal(err)
	}
	if ov.TotalValues != 26 { // a 25-value batch plus one refused call
		t.Fatalf("total_values = %d, want 26", ov.TotalValues)
	}
	if ov.RecordedSince == nil || ov.Scope != "standalone" || len(ov.ByNode) != 1 || ov.ByNode[0].TotalOps != 2 {
		t.Fatalf("overview = %+v", ov)
	}
	if empty, _ := store.GetOpsOverview(ctx, "nobody", "24h"); empty.RecordedSince != nil {
		t.Fatalf("recorded_since for a tenant with no operations: %v", empty.RecordedSince)
	}
}

// On the primary, a member's metered operation is counted under that
// member when the relay cursor passes it, in the same transaction, so the
// primary's metrics cover the cluster. Non-metered events only move the
// cursor.
func TestRelayCountsMemberOperationsOnce(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()
	member := keyOpEvent("t1", "sign", "success", 2)
	member.Sequence = 7
	if err := store.advanceRelay(ctx, "t1", "node-b", member); err != nil {
		t.Fatal(err)
	}
	other := AuditEvent{TenantID: "t1", Service: "auth", Action: "audit.auth.login", Result: "success", Sequence: 8, Timestamp: time.Now().UTC()}
	if err := store.advanceRelay(ctx, "t1", "node-b", other); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordOp(ctx, OpSample{TenantID: "t1", Node: "node-a", Service: "keycore", OpType: "sign", At: time.Now(), Latency: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	ov, err := store.GetOpsOverview(ctx, "t1", "24h")
	if err != nil {
		t.Fatal(err)
	}
	if ov.TotalOps != 2 || len(ov.ByNode) != 2 || ov.ByNode[0].Node != "node-a" || ov.ByNode[1].Node != "node-b" || ov.ByNode[1].TotalOps != 1 {
		t.Fatalf("overview = %+v", ov)
	}
	var last int64
	if err := store.db.SQL().QueryRowContext(ctx, `SELECT last_sequence FROM audit_relay_cursor WHERE tenant_id='t1' AND chain_node='node-b'`).Scan(&last); err != nil || last != 8 {
		t.Fatalf("relay cursor = %d, %v", last, err)
	}
}

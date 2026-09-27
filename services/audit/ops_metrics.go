package main

import (
	"context"
	"log"
	"math"
	"strings"
	"time"
)

// OpSample is one key operation taken from its audit event.
type OpSample struct {
	TenantID string
	Service  string
	OpType   string
	At       time.Time
	Latency  time.Duration
	IsError  bool
}

// latencyBucketsMs are the histogram upper bounds (lat_b00..lat_b11,
// migration 007); lat_b12 counts anything slower.
var latencyBucketsMs = []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 1000}

// latencyBucket is the histogram column index for a latency.
func latencyBucket(d time.Duration) int {
	ms := float64(d.Microseconds()) / 1000
	for i, le := range latencyBucketsMs {
		if ms <= le {
			return i
		}
	}
	return len(latencyBucketsMs)
}

// bucketPercentile returns the upper bound of the bucket holding quantile
// q, or nil if it is in the overflow bucket or there are no samples.
func bucketPercentile(counts []int64, total int64, q float64) *float64 {
	if total <= 0 {
		return nil
	}
	rank := int64(math.Ceil(q * float64(total)))
	var cum int64
	for i, c := range counts {
		cum += c
		if cum >= rank {
			if i >= len(latencyBucketsMs) {
				return nil
			}
			v := latencyBucketsMs[i]
			return &v
		}
	}
	return nil
}

// OpsOverview is the high-level aggregate view of operations.
type OpsOverview struct {
	TenantID       string    `json:"tenant_id"`
	Window         string    `json:"window"`
	TotalOps       int64     `json:"total_ops"`
	TotalErrors    int64     `json:"total_errors"`
	ErrorRate      float64   `json:"error_rate"`
	AvgLatencyMs   float64   `json:"avg_latency_ms"`
	TotalLatencyMs int64     `json:"total_latency_ms"`
	ComputedAt     time.Time `json:"computed_at"`
}

// OpsTimeSeries is a single hourly data point of operation statistics.
type OpsTimeSeries struct {
	Hour         time.Time `json:"hour"`
	TotalOps     int64     `json:"total_ops"`
	TotalErrors  int64     `json:"total_errors"`
	AvgLatencyMs float64   `json:"avg_latency_ms"`
}

// LatencyPercentiles are measured from the per-sample latency histogram:
// each percentile is the upper bound of the bucket that holds it, so "p99
// 2.5" means 99% of operations finished in 2.5 ms or less. A nil
// percentile fell in the overflow bucket (slower than the last bound).
type LatencyPercentiles struct {
	Service   string   `json:"service"`
	OpType    string   `json:"op_type"`
	AvgMs     float64  `json:"avg_ms"`
	P50Ms     *float64 `json:"p50_ms"`
	P90Ms     *float64 `json:"p90_ms"`
	P99Ms     *float64 `json:"p99_ms"`
	SampleOps int64    `json:"sample_ops"`
}

// ServiceOpsStats aggregates operation counts and error rates per service.
type ServiceOpsStats struct {
	Service      string  `json:"service"`
	TotalOps     int64   `json:"total_ops"`
	TotalErrors  int64   `json:"total_errors"`
	ErrorRate    float64 `json:"error_rate"`
	AvgLatencyMs float64 `json:"avg_latency_ms"`
}

// ErrorBreakdown aggregates error counts by op type.
type ErrorBreakdown struct {
	Service     string `json:"service"`
	OpType      string `json:"op_type"`
	ErrorCount  int64  `json:"error_count"`
	TotalCount  int64  `json:"total_count"`
}

// PrometheusMetricRow is a cross-tenant aggregate row for Prometheus exposition.
type PrometheusMetricRow struct {
	Service      string
	OpType       string
	TotalOps     int64
	TotalErrors  int64
	AvgLatencyMs float64
}

// windowHours maps a window label to hours.
func windowHours(window string) int {
	switch window {
	case "1h":
		return 1
	case "6h":
		return 6
	case "24h":
		return 24
	case "7d":
		return 168
	case "30d":
		return 720
	default:
		return 24
	}
}

// windowStart is the earliest hour bucket a window includes.
func windowStart(window string) time.Time {
	return time.Now().UTC().Add(-time.Duration(windowHours(window)) * time.Hour).Truncate(time.Hour)
}

// meteredKeyOps are the keycore operations the Operations metrics count.
// Keycore emits audit.key.<op> for each one it runs, refuses or fails
// (services/keycore/crypto_op_audit.go).
var meteredKeyOps = map[string]bool{
	"encrypt": true, "decrypt": true, "wrap": true, "unwrap": true,
	"sign": true, "verify": true, "mac": true, "derive": true,
	"kem_encapsulate": true, "kem_decapsulate": true,
}

// opSampleFromEvent turns a persisted key-operation event into a metrics
// sample. Anything else — other events, or an operation parked for
// approval — is not an operation that ran, and is not counted.
func opSampleFromEvent(evt AuditEvent) (OpSample, bool) {
	op, ok := strings.CutPrefix(evt.Action, "audit.key.")
	if !ok || !meteredKeyOps[op] || evt.Service != "keycore" {
		return OpSample{}, false
	}
	switch evt.Result {
	case "success", "failure", "refused":
	default:
		return OpSample{}, false
	}
	return OpSample{
		TenantID: evt.TenantID,
		Service:  evt.Service,
		OpType:   op,
		At:       evt.Timestamp,
		Latency:  time.Duration(evt.DurationMS * float64(time.Millisecond)),
		IsError:  evt.Result != "success",
	}, true
}

// recordOpMetric counts a key operation once its event is persisted. A
// metrics write never fails ingest: the event itself is the record.
func (s *Service) recordOpMetric(ctx context.Context, evt AuditEvent) {
	sample, ok := opSampleFromEvent(evt)
	if !ok {
		return
	}
	if err := s.store.RecordOp(ctx, sample); err != nil {
		log.Printf("audit: ops metric for %s %s not recorded: %v", evt.TenantID, evt.Action, err)
	}
}

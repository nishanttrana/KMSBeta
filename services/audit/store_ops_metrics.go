package main

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"vecta-kms/pkg/clusterstate"
)

type sqlExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// RecordOp adds one operation to its node's hour row: count, errors,
// summed latency (µs) and one histogram bucket.
func (s *SQLStore) RecordOp(ctx context.Context, op OpSample) error {
	return recordOp(ctx, s.db.SQL(), op)
}

func recordOp(ctx context.Context, db sqlExecer, op OpSample) error {
	hour := op.At.UTC().Truncate(time.Hour)
	errorCount := 0
	if op.IsError {
		errorCount = 1
	}
	bucket := fmt.Sprintf("lat_b%02d", latencyBucket(op.Latency))
	_, err := db.ExecContext(ctx, `
INSERT INTO ops_metrics_hourly (tenant_id, hour, node, service, op_type, count, error_count, total_latency_us, `+bucket+`)
VALUES ($1, $2, $3, $4, $5, 1, $6, $7, 1)
ON CONFLICT (tenant_id, hour, node, service, op_type) DO UPDATE
SET count            = ops_metrics_hourly.count + 1,
    error_count      = ops_metrics_hourly.error_count + $6,
    total_latency_us = ops_metrics_hourly.total_latency_us + $7,
    `+bucket+`       = ops_metrics_hourly.`+bucket+` + 1
`, op.TenantID, hour, op.Node, op.Service, op.OpType, errorCount, op.Latency.Microseconds())
	return err
}

// GetOpsOverview returns aggregate ops statistics for the given window.
func (s *SQLStore) GetOpsOverview(ctx context.Context, tenantID, window string) (OpsOverview, error) {
	since := windowStart(window)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(count),0),
    COALESCE(SUM(error_count),0),
    COALESCE(SUM(total_latency_us),0)
FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2
`, tenantID, since)
	var totalOps, totalErrors, totalLatency int64
	if err := row.Scan(&totalOps, &totalErrors, &totalLatency); err != nil {
		return OpsOverview{}, err
	}
	ov := OpsOverview{
		Scope:          s.opsScope(ctx),
		TenantID:       tenantID,
		Window:         window,
		TotalOps:       totalOps,
		TotalErrors:    totalErrors,
		TotalLatencyMs: totalLatency / 1000,
		ComputedAt:     time.Now().UTC(),
	}
	if totalOps > 0 {
		ov.ErrorRate = float64(totalErrors) / float64(totalOps)
		ov.AvgLatencyMs = float64(totalLatency) / 1000 / float64(totalOps)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT node, COALESCE(SUM(count),0) FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2 GROUP BY node ORDER BY node`, tenantID, since)
	if err != nil {
		return OpsOverview{}, err
	}
	defer rows.Close() //nolint:errcheck
	ov.ByNode = []NodeOps{}
	for rows.Next() {
		var n NodeOps
		if err := rows.Scan(&n.Node, &n.TotalOps); err != nil {
			return OpsOverview{}, err
		}
		ov.ByNode = append(ov.ByNode, n)
	}
	if err := rows.Err(); err != nil {
		return OpsOverview{}, err
	}
	var first interface{}
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT MIN(hour) FROM ops_metrics_hourly WHERE tenant_id=$1`, tenantID).Scan(&first); err != nil {
		return OpsOverview{}, err
	}
	if first != nil {
		if t := parseTimeValue(first); !t.IsZero() {
			ov.RecordedSince = &t
		}
	}
	return ov, nil
}

// GetOpsTimeSeries returns per-hour operation statistics for the given window.
func (s *SQLStore) GetOpsTimeSeries(ctx context.Context, tenantID, window string) ([]OpsTimeSeries, error) {
	since := windowStart(window)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    hour,
    COALESCE(SUM(count),0)           AS total_ops,
    COALESCE(SUM(error_count),0)     AS total_errors,
    COALESCE(SUM(total_latency_us),0) AS total_latency
FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2
GROUP BY hour
ORDER BY hour ASC
`, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []OpsTimeSeries
	for rows.Next() {
		var ts OpsTimeSeries
		var hourRaw interface{}
		var totalLatency int64
		if err := rows.Scan(&hourRaw, &ts.TotalOps, &ts.TotalErrors, &totalLatency); err != nil {
			return nil, err
		}
		ts.Hour = parseTimeValue(hourRaw)
		if ts.TotalOps > 0 {
			ts.AvgLatencyMs = float64(totalLatency) / 1000 / float64(ts.TotalOps)
		}
		out = append(out, ts)
	}
	return out, rows.Err()
}

// GetLatencyPercentiles returns per service+op_type latency: the exact
// average and p50/p90/p99 measured from the latency histogram.
func (s *SQLStore) GetLatencyPercentiles(ctx context.Context, tenantID, window string) ([]LatencyPercentiles, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    service,
    op_type,
    COALESCE(SUM(count),0),
    COALESCE(SUM(total_latency_us),0),
    COALESCE(SUM(lat_b00),0),
    COALESCE(SUM(lat_b01),0),
    COALESCE(SUM(lat_b02),0),
    COALESCE(SUM(lat_b03),0),
    COALESCE(SUM(lat_b04),0),
    COALESCE(SUM(lat_b05),0),
    COALESCE(SUM(lat_b06),0),
    COALESCE(SUM(lat_b07),0),
    COALESCE(SUM(lat_b08),0),
    COALESCE(SUM(lat_b09),0),
    COALESCE(SUM(lat_b10),0),
    COALESCE(SUM(lat_b11),0),
    COALESCE(SUM(lat_b12),0)
FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2
GROUP BY service, op_type
ORDER BY service, op_type
`, tenantID, windowStart(window))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []LatencyPercentiles
	for rows.Next() {
		var p LatencyPercentiles
		var totalLatency int64
		buckets := make([]int64, len(latencyBucketsMs)+1)
		dest := []any{&p.Service, &p.OpType, &p.SampleOps, &totalLatency}
		for i := range buckets {
			dest = append(dest, &buckets[i])
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		if p.SampleOps > 0 {
			p.AvgMs = float64(totalLatency) / 1000 / float64(p.SampleOps)
		}
		var sampled int64
		for _, c := range buckets {
			sampled += c
		}
		p.P50Ms = bucketPercentile(buckets, sampled, 0.50)
		p.P90Ms = bucketPercentile(buckets, sampled, 0.90)
		p.P99Ms = bucketPercentile(buckets, sampled, 0.99)
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetServiceStats returns aggregate operation statistics grouped by service.
func (s *SQLStore) GetServiceStats(ctx context.Context, tenantID, window string) ([]ServiceOpsStats, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    service,
    COALESCE(SUM(count),0)              AS total_ops,
    COALESCE(SUM(error_count),0)        AS total_errors,
    COALESCE(SUM(total_latency_us),0)   AS total_latency
FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2
GROUP BY service
ORDER BY total_ops DESC
`, tenantID, windowStart(window))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ServiceOpsStats
	for rows.Next() {
		var ss ServiceOpsStats
		var totalLatency int64
		if err := rows.Scan(&ss.Service, &ss.TotalOps, &ss.TotalErrors, &totalLatency); err != nil {
			return nil, err
		}
		if ss.TotalOps > 0 {
			ss.ErrorRate = float64(ss.TotalErrors) / float64(ss.TotalOps)
			ss.AvgLatencyMs = float64(totalLatency) / 1000 / float64(ss.TotalOps)
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}

// GetAllServiceStats returns cross-tenant per-service/op-type aggregates for Prometheus.
func (s *SQLStore) GetAllServiceStats(ctx context.Context) ([]PrometheusMetricRow, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    service,
    op_type,
    COALESCE(SUM(count),0)              AS total_ops,
    COALESCE(SUM(error_count),0)        AS total_errors,
    COALESCE(SUM(total_latency_us),0)   AS total_latency
FROM ops_metrics_hourly
GROUP BY service, op_type
ORDER BY service, op_type
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []PrometheusMetricRow
	for rows.Next() {
		var r PrometheusMetricRow
		var totalLatency int64
		if err := rows.Scan(&r.Service, &r.OpType, &r.TotalOps, &r.TotalErrors, &totalLatency); err != nil {
			return nil, err
		}
		if r.TotalOps > 0 {
			r.AvgLatencyMs = float64(totalLatency) / 1000 / float64(r.TotalOps)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetErrorBreakdown returns error counts broken down by service and op_type.
func (s *SQLStore) GetErrorBreakdown(ctx context.Context, tenantID, window string) ([]ErrorBreakdown, error) {
	since := windowStart(window)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    service,
    op_type,
    COALESCE(SUM(error_count),0) AS error_count,
    COALESCE(SUM(count),0)       AS total_count
FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2
GROUP BY service, op_type
HAVING SUM(error_count) > 0
ORDER BY error_count DESC
`, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []ErrorBreakdown
	for rows.Next() {
		var eb ErrorBreakdown
		if err := rows.Scan(&eb.Service, &eb.OpType, &eb.ErrorCount, &eb.TotalCount); err != nil {
			return nil, err
		}
		out = append(out, eb)
	}
	return out, rows.Err()
}

// opsScope is what this node's metrics cover: every node's operations on
// a cluster primary (it counts members' relayed events), only its own on
// a member, or the single node when unclustered.
func (s *SQLStore) opsScope(ctx context.Context) string {
	switch {
	case s.chainNode(ctx) == "":
		return "standalone"
	case clusterstate.RunsPrimaryJobs(ctx):
		return "cluster"
	default:
		return "node"
	}
}

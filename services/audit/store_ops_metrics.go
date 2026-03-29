package main

import (
	"context"
	"time"
)

// RecordOp upserts an operation record into ops_metrics_hourly.
func (s *SQLStore) RecordOp(ctx context.Context, tenantID, service, opType string, latencyMs int, isError bool) error {
	hour := time.Now().UTC().Truncate(time.Hour)
	errorCount := 0
	if isError {
		errorCount = 1
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO ops_metrics_hourly (tenant_id, hour, service, op_type, count, error_count, total_latency_ms)
VALUES ($1, $2, $3, $4, 1, $5, $6)
ON CONFLICT (tenant_id, hour, service, op_type) DO UPDATE
SET count           = ops_metrics_hourly.count + 1,
    error_count     = ops_metrics_hourly.error_count + $5,
    total_latency_ms = ops_metrics_hourly.total_latency_ms + $6
`, tenantID, hour, service, opType, errorCount, latencyMs)
	return err
}

// GetOpsOverview returns aggregate ops statistics for the given window.
func (s *SQLStore) GetOpsOverview(ctx context.Context, tenantID, window string) (OpsOverview, error) {
	hours := windowHours(window)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT
    COALESCE(SUM(count),0),
    COALESCE(SUM(error_count),0),
    COALESCE(SUM(total_latency_ms),0)
FROM ops_metrics_hourly
WHERE tenant_id=$1 AND hour >= $2
`, tenantID, since)
	var totalOps, totalErrors, totalLatency int64
	if err := row.Scan(&totalOps, &totalErrors, &totalLatency); err != nil {
		return OpsOverview{}, err
	}
	ov := OpsOverview{
		TenantID:       tenantID,
		Window:         window,
		TotalOps:       totalOps,
		TotalErrors:    totalErrors,
		TotalLatencyMs: totalLatency,
		ComputedAt:     time.Now().UTC(),
	}
	if totalOps > 0 {
		ov.ErrorRate = float64(totalErrors) / float64(totalOps)
		ov.AvgLatencyMs = float64(totalLatency) / float64(totalOps)
	}
	return ov, nil
}

// GetOpsTimeSeries returns per-hour operation statistics for the given window.
func (s *SQLStore) GetOpsTimeSeries(ctx context.Context, tenantID, window string) ([]OpsTimeSeries, error) {
	hours := windowHours(window)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    hour,
    COALESCE(SUM(count),0)           AS total_ops,
    COALESCE(SUM(error_count),0)     AS total_errors,
    COALESCE(SUM(total_latency_ms),0) AS total_latency
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
			ts.AvgLatencyMs = float64(totalLatency) / float64(ts.TotalOps)
		}
		out = append(out, ts)
	}
	return out, rows.Err()
}

// GetLatencyPercentiles returns estimated latency percentiles per service+op_type.
// Since raw events are not stored individually, percentiles are approximated from
// aggregate data: avg is exact; p50/p90/p99 are estimated from the average using
// standard distribution heuristics (p50 ≈ avg, p90 ≈ 2×avg, p99 ≈ 4×avg).
func (s *SQLStore) GetLatencyPercentiles(ctx context.Context, tenantID string) ([]LatencyPercentiles, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    service,
    op_type,
    COALESCE(SUM(count),0)              AS sample_ops,
    COALESCE(SUM(total_latency_ms),0)   AS total_latency
FROM ops_metrics_hourly
WHERE tenant_id=$1
GROUP BY service, op_type
ORDER BY service, op_type
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []LatencyPercentiles
	for rows.Next() {
		var p LatencyPercentiles
		var totalLatency int64
		if err := rows.Scan(&p.Service, &p.OpType, &p.SampleOps, &totalLatency); err != nil {
			return nil, err
		}
		if p.SampleOps > 0 {
			p.AvgMs = float64(totalLatency) / float64(p.SampleOps)
		}
		p.P50Ms = p.AvgMs
		p.P90Ms = p.AvgMs * 2.0
		p.P99Ms = p.AvgMs * 4.0
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetServiceStats returns aggregate operation statistics grouped by service.
func (s *SQLStore) GetServiceStats(ctx context.Context, tenantID string) ([]ServiceOpsStats, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT
    service,
    COALESCE(SUM(count),0)              AS total_ops,
    COALESCE(SUM(error_count),0)        AS total_errors,
    COALESCE(SUM(total_latency_ms),0)   AS total_latency
FROM ops_metrics_hourly
WHERE tenant_id=$1
GROUP BY service
ORDER BY total_ops DESC
`, tenantID)
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
			ss.AvgLatencyMs = float64(totalLatency) / float64(ss.TotalOps)
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
    COALESCE(SUM(total_latency_ms),0)   AS total_latency
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
			r.AvgLatencyMs = float64(totalLatency) / float64(r.TotalOps)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetErrorBreakdown returns error counts broken down by service and op_type.
func (s *SQLStore) GetErrorBreakdown(ctx context.Context, tenantID, window string) ([]ErrorBreakdown, error) {
	hours := windowHours(window)
	since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
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

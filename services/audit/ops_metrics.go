package main

import "time"

// OpsMetricsWindow defines the time window for ops metrics queries.
type OpsMetricsWindow struct {
	Label string
	Hours int
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

// LatencyPercentiles represents computed latency percentile estimates by op type.
type LatencyPercentiles struct {
	Service   string  `json:"service"`
	OpType    string  `json:"op_type"`
	AvgMs     float64 `json:"avg_ms"`
	P50Ms     float64 `json:"p50_ms"`
	P90Ms     float64 `json:"p90_ms"`
	P99Ms     float64 `json:"p99_ms"`
	SampleOps int64   `json:"sample_ops"`
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

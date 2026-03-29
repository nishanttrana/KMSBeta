package main

import (
	"fmt"
	"net/http"
	"strings"
)

// handlePrometheusMetrics serves Prometheus-compatible metrics in text exposition format.
// Endpoint: GET /metrics
//
// Exposes per-service operation counters, error counters, and average latency
// derived from the ops_metrics_hourly table (all-time aggregates, all tenants).
func (h *Handler) handlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Aggregate across all tenants by querying with empty tenant (system-wide).
	// We use a special internal query that ignores tenant_id filter.
	rows, err := h.store.GetAllServiceStats(ctx)
	if err != nil {
		http.Error(w, "# ERROR: "+err.Error()+"\n", http.StatusInternalServerError)
		return
	}

	var sb strings.Builder

	// HELP and TYPE headers
	sb.WriteString("# HELP kms_ops_total Total number of KMS operations by service and op_type.\n")
	sb.WriteString("# TYPE kms_ops_total counter\n")
	for _, s := range rows {
		sb.WriteString(fmt.Sprintf(
			"kms_ops_total{service=%q,op_type=%q} %d\n",
			s.Service, s.OpType, s.TotalOps,
		))
	}

	sb.WriteString("# HELP kms_ops_errors_total Total number of failed KMS operations by service and op_type.\n")
	sb.WriteString("# TYPE kms_ops_errors_total counter\n")
	for _, s := range rows {
		sb.WriteString(fmt.Sprintf(
			"kms_ops_errors_total{service=%q,op_type=%q} %d\n",
			s.Service, s.OpType, s.TotalErrors,
		))
	}

	sb.WriteString("# HELP kms_ops_latency_avg_ms Average operation latency in milliseconds by service and op_type.\n")
	sb.WriteString("# TYPE kms_ops_latency_avg_ms gauge\n")
	for _, s := range rows {
		sb.WriteString(fmt.Sprintf(
			"kms_ops_latency_avg_ms{service=%q,op_type=%q} %.3f\n",
			s.Service, s.OpType, s.AvgLatencyMs,
		))
	}

	// Aggregate totals per service (for dashboard panels)
	// Compute from per-op rows.
	type svcAgg struct {
		totalOps    int64
		totalErrors int64
		totalLatMs  float64
	}
	svcMap := map[string]*svcAgg{}
	for _, s := range rows {
		a := svcMap[s.Service]
		if a == nil {
			a = &svcAgg{}
			svcMap[s.Service] = a
		}
		a.totalOps += s.TotalOps
		a.totalErrors += s.TotalErrors
		a.totalLatMs += s.AvgLatencyMs * float64(s.TotalOps)
	}

	sb.WriteString("# HELP kms_service_ops_total Total operations per KMS service.\n")
	sb.WriteString("# TYPE kms_service_ops_total counter\n")
	for svc, a := range svcMap {
		sb.WriteString(fmt.Sprintf("kms_service_ops_total{service=%q} %d\n", svc, a.totalOps))
	}

	sb.WriteString("# HELP kms_service_errors_total Total errors per KMS service.\n")
	sb.WriteString("# TYPE kms_service_errors_total counter\n")
	for svc, a := range svcMap {
		sb.WriteString(fmt.Sprintf("kms_service_errors_total{service=%q} %d\n", svc, a.totalErrors))
	}

	sb.WriteString("# HELP kms_service_error_rate Fraction of operations that resulted in errors per service (0–1).\n")
	sb.WriteString("# TYPE kms_service_error_rate gauge\n")
	for svc, a := range svcMap {
		rate := 0.0
		if a.totalOps > 0 {
			rate = float64(a.totalErrors) / float64(a.totalOps)
		}
		sb.WriteString(fmt.Sprintf("kms_service_error_rate{service=%q} %.6f\n", svc, rate))
	}

	sb.WriteString("# HELP kms_service_latency_avg_ms Average operation latency in milliseconds per service.\n")
	sb.WriteString("# TYPE kms_service_latency_avg_ms gauge\n")
	for svc, a := range svcMap {
		avg := 0.0
		if a.totalOps > 0 {
			avg = a.totalLatMs / float64(a.totalOps)
		}
		sb.WriteString(fmt.Sprintf("kms_service_latency_avg_ms{service=%q} %.3f\n", svc, avg))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}

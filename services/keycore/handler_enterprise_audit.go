package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (h *Handler) handleGetEnterpriseAuditSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.GetEnterpriseAuditSummary(r.Context(), tenantID, daysQuery(r, 30))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "enterprise_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleGetRotationAnalytics(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.store.GetRotationAnalyticsSummary(r.Context(), tenantID, daysQuery(r, 30))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rotation_analytics_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleListOverdueRotationMetrics(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListOverdueRotationMetrics(r.Context(), tenantID, limitQuery(r, 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "overdue_rotation_metrics_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleListKeyRotationMetrics(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListRotationMetrics(r.Context(), tenantID, r.PathValue("id"), strings.TrimSpace(r.URL.Query().Get("status")), limitQuery(r, 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key_rotation_metrics_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleRecordKeyRotationMetric(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var metric RotationMetric
	if err := decodeJSON(r, &metric); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	metric.TenantID = tenantID
	metric.KeyID = r.PathValue("id")
	if strings.TrimSpace(metric.RotationID) == "" {
		metric.RotationID = newID("rotm")
	}
	if metric.ScheduledDate.IsZero() {
		metric.ScheduledDate = time.Now().UTC()
	}
	if strings.TrimSpace(metric.Status) == "" {
		metric.Status = "scheduled"
	}
	if err := h.svc.store.RecordRotationMetric(r.Context(), metric); err != nil {
		writeErr(w, http.StatusInternalServerError, "record_rotation_metric_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"metric": metric, "request_id": reqID})
}

func (h *Handler) handleGetKeyHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if truthy(r.URL.Query().Get("recalculate")) {
		h.handleRecalculateKeyHealth(w, r)
		return
	}
	score, err := h.svc.store.GetKeyHealthScore(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errStoreNotFound) {
		score, err = h.svc.CalculateKeyHealth(r.Context(), tenantID, r.PathValue("id"))
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key_health_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": score, "request_id": reqID})
}

func (h *Handler) handleRecalculateKeyHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	score, err := h.svc.CalculateKeyHealth(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "key_health_recalculate_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": score, "request_id": reqID})
}

func (h *Handler) handleGetHealthSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.store.GetKeyHealthSummary(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "health_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	items, err := h.svc.store.ListKeyHealthScores(r.Context(), tenantID, limitQuery(r, 50))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "health_scores_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "items": items, "request_id": reqID})
}

func (h *Handler) handleSyncInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.SyncKeyInventory(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "inventory_sync_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleListInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListInventoryItems(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("owner")), limitQuery(r, 200), offsetQuery(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "inventory_list_failed", err.Error(), reqID, tenantID)
		return
	}
	duplicates, _ := h.svc.DetectDuplicateKeys(r.Context(), tenantID)
	summary, _ := h.svc.store.GetInventorySummary(r.Context(), tenantID, len(duplicates))
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "items": items, "request_id": reqID})
}

func (h *Handler) handleListOrphanedInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListOrphanedInventoryItems(r.Context(), tenantID, limitQuery(r, 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "orphaned_inventory_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleListDuplicateKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.DetectDuplicateKeys(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "duplicate_detection_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleListKeyDependencies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListKeyDependencies(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("key_id")), limitQuery(r, 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "dependency_list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertKeyDependencyRecord(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var dep KeyDependencyRecord
	if err := decodeJSON(r, &dep); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	dep.TenantID = tenantID
	if strings.TrimSpace(dep.KeyID) == "" || strings.TrimSpace(dep.ServiceID) == "" || strings.TrimSpace(dep.DependencyType) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "key_id, service_id, and dependency_type are required", reqID, tenantID)
		return
	}
	if err := h.svc.store.UpsertKeyDependencyRecord(r.Context(), dep); err != nil {
		writeErr(w, http.StatusInternalServerError, "dependency_upsert_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"dependency": dep, "request_id": reqID})
}

func (h *Handler) handleListCompromiseEvents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListCompromiseEvents(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("status")), strings.TrimSpace(r.URL.Query().Get("severity")), limitQuery(r, 200))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "compromise_events_failed", err.Error(), reqID, tenantID)
		return
	}
	summary, _ := h.svc.store.GetCompromiseSummary(r.Context(), tenantID)
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "items": items, "request_id": reqID})
}

func (h *Handler) handleReportCompromiseEvent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		KeyID             string         `json:"key_id"`
		CVEID             string         `json:"cve_id"`
		ThreatType        string         `json:"threat_type"`
		Severity          string         `json:"severity"`
		Status            string         `json:"status"`
		RemediationPlan   string         `json:"remediation_plan"`
		RemediationStatus string         `json:"remediation_status"`
		AffectedSystems   []string       `json:"affected_systems"`
		NotificationsSent []string       `json:"notifications_sent"`
		RootCause         string         `json:"root_cause"`
		DetectionSource   string         `json:"detection_source"`
		Metadata          map[string]any `json:"metadata"`
		AutoSuspend       bool           `json:"auto_suspend"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.KeyID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "key_id is required", reqID, tenantID)
		return
	}
	event, err := h.svc.ReportCompromiseEvent(r.Context(), CompromiseEvent{
		TenantID:          tenantID,
		KeyID:             req.KeyID,
		CVEID:             req.CVEID,
		ThreatType:        req.ThreatType,
		Severity:          req.Severity,
		Status:            req.Status,
		RemediationPlan:   req.RemediationPlan,
		RemediationStatus: req.RemediationStatus,
		AffectedSystems:   req.AffectedSystems,
		NotificationsSent: req.NotificationsSent,
		RootCause:         req.RootCause,
		DetectionSource:   req.DetectionSource,
		Metadata:          req.Metadata,
	}, req.AutoSuspend)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "compromise_report_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"event": event, "request_id": reqID})
}

func (h *Handler) handleUpdateCompromiseEventStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Status            string   `json:"status"`
		RemediationStatus string   `json:"remediation_status"`
		RootCause         string   `json:"root_cause"`
		NotificationsSent []string `json:"notifications_sent"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	event, err := h.svc.store.UpdateCompromiseEventStatus(r.Context(), tenantID, r.PathValue("id"), req.Status, req.RemediationStatus, req.RootCause, req.NotificationsSent)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "compromise_status_update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"event": event, "request_id": reqID})
}

func (h *Handler) handleIngestCompromiseAdvisories(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Advisories  []CompromiseAdvisory `json:"advisories"`
		AutoSuspend bool                 `json:"auto_suspend"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	result, err := h.svc.IngestCompromiseAdvisories(r.Context(), tenantID, req.Advisories, req.AutoSuspend)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "advisory_ingest_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"result": result, "request_id": reqID})
}

func (h *Handler) handleRecordKeyAnalyticsMetric(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var metric KeyAnalyticsMetric
	if err := decodeJSON(r, &metric); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	metric.TenantID = tenantID
	if strings.TrimSpace(metric.MetricType) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "metric_type is required", reqID, tenantID)
		return
	}
	if err := h.svc.store.RecordKeyAnalyticsMetric(r.Context(), metric); err != nil {
		writeErr(w, http.StatusInternalServerError, "metric_record_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"metric": metric, "request_id": reqID})
}

func (h *Handler) handleGetKeyUsageMetrics(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.store.GetKeyUsageMetricSummary(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("key_id")), sinceQuery(r, 1))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "usage_metrics_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleListKeyHotspots(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListKeyHotspots(r.Context(), tenantID, sinceQuery(r, 7), limitQuery(r, 20))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hotspots_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetKeyTrend(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	metricType := strings.TrimSpace(r.URL.Query().Get("metric_type"))
	if metricType == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "metric_type is required", reqID, tenantID)
		return
	}
	items, err := h.svc.store.GetKeyTrend(r.Context(), tenantID, metricType, sinceQuery(r, 30))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "trend_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetAlgorithmBenchmarks(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.GetAlgorithmBenchmarks(r.Context(), tenantID, sinceQuery(r, 7))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "algorithm_benchmarks_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func limitQuery(r *http.Request, defaultLimit int) int {
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	if limit <= 0 {
		return defaultLimit
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func offsetQuery(r *http.Request) int {
	offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
	if offset < 0 {
		return 0
	}
	return offset
}

func daysQuery(r *http.Request, defaultDays int) int {
	days, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("days")))
	if days <= 0 {
		return defaultDays
	}
	if days > 3650 {
		return 3650
	}
	return days
}

func sinceQuery(r *http.Request, defaultDays int) time.Time {
	if raw := strings.TrimSpace(r.URL.Query().Get("since")); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC().AddDate(0, 0, -daysQuery(r, defaultDays))
}

func truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

type Handler struct {
	svc          *Service
	mux          *http.ServeMux
	releaseTag   string
	buildVersion string
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{
		svc:          svc,
		releaseTag:   firstNonEmpty(strings.TrimSpace(os.Getenv("RELEASE_TAG")), "reporting"),
		buildVersion: firstNonEmpty(strings.TrimSpace(os.Getenv("BUILD_VERSION")), "dev"),
	}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := firstNonEmpty(tenantFromRequest(r), "root")
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		message := fmt.Sprintf("panic recovered in reporting handler: %v", rec)
		_, _ = h.svc.CaptureErrorTelemetry(context.Background(), tenantID, ErrorTelemetryEvent{
			Source:     "backend",
			Service:    "reporting",
			Component:  firstNonEmpty(r.Method+" "+r.URL.Path, "http"),
			Level:      "critical",
			Message:    message,
			StackTrace: string(debug.Stack()),
			Context: map[string]interface{}{
				"method": r.Method,
				"path":   r.URL.Path,
			},
			RequestID:  reqID,
			ReleaseTag: h.releaseTag,
			BuildVer:   h.buildVersion,
		})
		writeErr(w, http.StatusInternalServerError, "internal_error", "internal server error", reqID, tenantID)
	}()
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /alerts", h.handleAlerts)
	mux.HandleFunc("GET /alerts/feed", h.handleAlertsFeed)
	mux.HandleFunc("GET /alerts/unread", h.handleAlertsUnread)
	mux.HandleFunc("GET /alerts/{id}", h.handleAlert)
	mux.HandleFunc("PUT /alerts/", h.handleAlertPutRouter)
	mux.HandleFunc("POST /alerts/bulk/acknowledge", h.handleBulkAcknowledge)
	mux.HandleFunc("POST /alerts/bulk/resolve", h.handleBulkResolve)

	mux.HandleFunc("GET /incidents", h.handleIncidents)
	mux.HandleFunc("GET /incidents/{id}", h.handleIncident)
	mux.HandleFunc("PUT /incidents/{id}/status", h.handleIncidentStatus)
	mux.HandleFunc("PUT /incidents/{id}/assign", h.handleIncidentAssign)

	mux.HandleFunc("GET /alerts/rules", h.handleListRules)
	mux.HandleFunc("POST /alerts/rules", h.handleCreateRule)
	mux.HandleFunc("PUT /alerts/rules/{id}", h.handleUpdateRule)
	mux.HandleFunc("DELETE /alerts/rules/{id}", h.handleDeleteRule)
	mux.HandleFunc("GET /alerts/severity-config", h.handleGetSeverityConfig)
	mux.HandleFunc("PUT /alerts/severity-config", h.handleUpdateSeverityConfig)
	mux.HandleFunc("GET /alerts/channels", h.handleListChannels)
	mux.HandleFunc("PUT /alerts/channels", h.handleUpdateChannels)

	mux.HandleFunc("GET /reports/templates", h.handleReportTemplates)
	mux.HandleFunc("POST /reports/generate", h.handleGenerateReport)
	mux.HandleFunc("GET /reports/jobs", h.handleListReportJobs)
	mux.HandleFunc("GET /reports/jobs/{id}", h.handleReportJob)
	mux.HandleFunc("GET /reports/jobs/{id}/download", h.handleReportDownload)
	mux.HandleFunc("DELETE /reports/jobs/{id}", h.handleDeleteReportJob)
	mux.HandleFunc("GET /reports/scheduled", h.handleListScheduledReports)
	mux.HandleFunc("POST /reports/scheduled", h.handleCreateScheduledReport)
	mux.HandleFunc("POST /telemetry/errors", h.handleCaptureErrorTelemetry)
	mux.HandleFunc("GET /telemetry/errors", h.handleListErrorTelemetry)

	mux.HandleFunc("GET /alerts/stats", h.handleAlertStats)
	mux.HandleFunc("GET /alerts/stats/mttr", h.handleMTTRStats)
	mux.HandleFunc("GET /alerts/stats/top-sources", h.handleTopSources)

	return mux
}

func (h *Handler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	q := AlertQuery{
		Severity:   strings.ToLower(strings.TrimSpace(r.URL.Query().Get("severity"))),
		Status:     strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status"))),
		Action:     strings.TrimSpace(r.URL.Query().Get("action")),
		TargetType: strings.TrimSpace(r.URL.Query().Get("target_type")),
		TargetID:   strings.TrimSpace(r.URL.Query().Get("target_id")),
		Limit:      atoi(r.URL.Query().Get("limit")),
		Offset:     atoi(r.URL.Query().Get("offset")),
	}
	q.From = parseTimeString(r.URL.Query().Get("from"))
	q.To = parseTimeString(r.URL.Query().Get("to"))
	items, err := h.svc.ListAlerts(r.Context(), tenantID, q)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleAlertsFeed(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}

	// SSE stream used for real-time feed.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "stream_error", "streaming not supported", reqID, tenantID)
		return
	}
	ch, cancel := h.svc.hub.Subscribe(tenantID)
	defer cancel()
	writeSSE(w, "ready", map[string]interface{}{"request_id": reqID, "tenant_id": tenantID})
	flusher.Flush()

	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case item := <-ch:
			writeSSE(w, "alert", item)
			flusher.Flush()
		case <-tick.C:
			writeSSE(w, "keepalive", map[string]interface{}{"timestamp": time.Now().UTC().Format(time.RFC3339)})
			flusher.Flush()
		}
	}
}

func (h *Handler) handleAlertsUnread(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.CountUnread(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"counts": out, "request_id": reqID})
}

func (h *Handler) handleAlert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, event, err := h.svc.GetAlert(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alert":       item,
		"audit_event": event,
		"request_id":  reqID,
	})
}

func (h *Handler) handleAcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	h.handleSingleStatusUpdate(w, r, "acknowledged")
}

func (h *Handler) handleResolveAlert(w http.ResponseWriter, r *http.Request) {
	h.handleSingleStatusUpdate(w, r, "resolved")
}

func (h *Handler) handleFalsePositiveAlert(w http.ResponseWriter, r *http.Request) {
	h.handleSingleStatusUpdate(w, r, "false_positive")
}

func (h *Handler) handleAlertPutRouter(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.Trim(strings.TrimSpace(r.URL.Path), "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 || !strings.EqualFold(parts[0], "alerts") {
		reqID := requestID(r)
		writeErr(w, http.StatusNotFound, "not_found", "endpoint not found", reqID, tenantFromRequest(r))
		return
	}
	id := parts[1]
	action := parts[2]
	switch action {
	case "acknowledge":
		r.SetPathValue("id", id)
		h.handleAcknowledgeAlert(w, r)
	case "resolve":
		r.SetPathValue("id", id)
		h.handleResolveAlert(w, r)
	case "false-positive":
		r.SetPathValue("id", id)
		h.handleFalsePositiveAlert(w, r)
	case "escalate":
		r.SetPathValue("id", id)
		h.handleEscalateAlert(w, r)
	default:
		reqID := requestID(r)
		writeErr(w, http.StatusNotFound, "not_found", "unsupported alert action", reqID, tenantFromRequest(r))
	}
}

func (h *Handler) handleSingleStatusUpdate(w http.ResponseWriter, r *http.Request, status string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body struct {
		Actor string `json:"actor"`
		Note  string `json:"note"`
	}
	_ = decodeJSON(r, &body)
	actor := defaultString(body.Actor, "system")
	var err error
	switch status {
	case "acknowledged":
		err = h.svc.AcknowledgeAlert(r.Context(), tenantID, r.PathValue("id"), actor)
	case "resolved":
		err = h.svc.ResolveAlert(r.Context(), tenantID, r.PathValue("id"), actor, body.Note)
	case "false_positive":
		err = h.svc.MarkFalsePositive(r.Context(), tenantID, r.PathValue("id"), actor, body.Note)
	}
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleEscalateAlert(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body struct {
		Severity string `json:"severity"`
	}
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.EscalateAlert(r.Context(), tenantID, r.PathValue("id"), body.Severity); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleBulkAcknowledge(w http.ResponseWriter, r *http.Request) {
	h.handleBulkStatusUpdate(w, r, "acknowledged")
}

func (h *Handler) handleBulkResolve(w http.ResponseWriter, r *http.Request) {
	h.handleBulkStatusUpdate(w, r, "resolved")
}

func (h *Handler) handleBulkStatusUpdate(w http.ResponseWriter, r *http.Request, status string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body struct {
		IDs    []string `json:"ids"`
		Actor  string   `json:"actor"`
		Note   string   `json:"note"`
		Status string   `json:"status"`
	}
	_ = decodeJSON(r, &body)
	q := AlertQuery{
		Severity: strings.TrimSpace(r.URL.Query().Get("severity")),
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Action:   strings.TrimSpace(r.URL.Query().Get("action")),
		Limit:    1000,
	}
	n, err := h.svc.BulkAlertStatus(r.Context(), tenantID, body.IDs, q, status, defaultString(body.Actor, "system"), body.Note)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"updated": n, "request_id": reqID})
}

func (h *Handler) handleIncidents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListIncidents(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")), atoi(r.URL.Query().Get("offset")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleIncident(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, alerts, err := h.svc.GetIncident(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"incident": item, "alerts": alerts, "request_id": reqID})
}

func (h *Handler) handleIncidentStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body struct {
		Status string `json:"status"`
		Notes  string `json:"notes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateIncidentStatus(r.Context(), tenantID, r.PathValue("id"), body.Status, body.Notes); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleIncidentAssign(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body struct {
		AssignedTo string `json:"assigned_to"`
	}
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.AssignIncident(r.Context(), tenantID, r.PathValue("id"), body.AssignedTo); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListRules(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListRules(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body AlertRule
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	item, err := h.svc.CreateRule(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body AlertRule
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateRule(r.Context(), tenantID, r.PathValue("id"), body); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteRule(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleGetSeverityConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	cfg, err := h.svc.GetSeverityConfig(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": cfg, "request_id": reqID})
}

func (h *Handler) handleUpdateSeverityConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body map[string]string
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateSeverityConfig(r.Context(), tenantID, body); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListChannels(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListChannels(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpdateChannels(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body []NotificationChannel
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateChannels(r.Context(), tenantID, body); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleReportTemplates(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": h.svc.Templates(), "request_id": reqID})
}

func (h *Handler) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID    string                 `json:"tenant_id"`
		TemplateID  string                 `json:"template_id"`
		Format      string                 `json:"format"`
		RequestedBy string                 `json:"requested_by"`
		Filters     map[string]interface{} `json:"filters"`
	}
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(body.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	job, err := h.svc.GenerateReport(r.Context(), body.TenantID, body.TemplateID, body.Format, body.RequestedBy, body.Filters)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"job": job, "request_id": reqID})
}

func (h *Handler) handleReportJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	job, err := h.svc.GetReportJob(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job": job, "request_id": reqID})
}

func (h *Handler) handleListReportJobs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	offset := atoi(r.URL.Query().Get("offset"))
	items, err := h.svc.ListReportJobs(r.Context(), tenantID, limit, offset)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	job, err := h.svc.GetReportJob(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	if job.Status != "completed" {
		writeErr(w, http.StatusConflict, "not_ready", "report job not completed", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"content":       job.ResultContent,
		"content_type":  job.ResultContentType,
		"template_id":   job.TemplateID,
		"generated_at":  job.CompletedAt,
		"report_job_id": job.ID,
		"request_id":    reqID,
	})
}

func (h *Handler) handleDeleteReportJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	actor := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("actor")), strings.TrimSpace(r.Header.Get("X-Actor-ID")), "dashboard")
	if err := h.svc.DeleteReportJob(r.Context(), tenantID, r.PathValue("id"), actor); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "request_id": reqID})
}

func (h *Handler) handleListScheduledReports(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListScheduledReports(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateScheduledReport(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID   string                 `json:"tenant_id"`
		Name       string                 `json:"name"`
		TemplateID string                 `json:"template_id"`
		Format     string                 `json:"format"`
		Schedule   string                 `json:"schedule"`
		Recipients []string               `json:"recipients"`
		Filters    map[string]interface{} `json:"filters"`
	}
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	if body.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	item, err := h.svc.ScheduleReport(r.Context(), body.TenantID, body.Name, body.TemplateID, body.Format, body.Schedule, body.Recipients, body.Filters)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleCaptureErrorTelemetry(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID    string                 `json:"tenant_id"`
		Source      string                 `json:"source"`
		Service     string                 `json:"service"`
		Component   string                 `json:"component"`
		Level       string                 `json:"level"`
		Message     string                 `json:"message"`
		StackTrace  string                 `json:"stack_trace"`
		Context     map[string]interface{} `json:"context"`
		Fingerprint string                 `json:"fingerprint"`
		RequestID   string                 `json:"request_id"`
		ReleaseTag  string                 `json:"release_tag"`
		BuildVer    string                 `json:"build_version"`
	}
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	if strings.TrimSpace(body.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(body.Message) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "message is required", reqID, body.TenantID)
		return
	}
	item, err := h.svc.CaptureErrorTelemetry(r.Context(), body.TenantID, ErrorTelemetryEvent{
		Source:      body.Source,
		Service:     body.Service,
		Component:   body.Component,
		Level:       body.Level,
		Message:     body.Message,
		StackTrace:  body.StackTrace,
		Context:     body.Context,
		Fingerprint: body.Fingerprint,
		RequestID:   firstNonEmpty(body.RequestID, reqID),
		ReleaseTag:  body.ReleaseTag,
		BuildVer:    body.BuildVer,
	})
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleListErrorTelemetry(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	q := ErrorTelemetryQuery{
		Source:      strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source"))),
		Service:     strings.ToLower(strings.TrimSpace(r.URL.Query().Get("service"))),
		Component:   strings.ToLower(strings.TrimSpace(r.URL.Query().Get("component"))),
		Level:       strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level"))),
		Fingerprint: strings.TrimSpace(r.URL.Query().Get("fingerprint")),
		RequestID:   strings.TrimSpace(r.URL.Query().Get("request_id")),
		Limit:       atoi(r.URL.Query().Get("limit")),
		Offset:      atoi(r.URL.Query().Get("offset")),
	}
	q.From = parseTimeString(r.URL.Query().Get("from"))
	q.To = parseTimeString(r.URL.Query().Get("to"))
	items, err := h.svc.ListErrorTelemetry(r.Context(), tenantID, q)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleAlertStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.AlertStats(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"stats": out, "request_id": reqID})
}

func (h *Handler) handleMTTRStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.MTTRStats(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"mttr_minutes": out, "request_id": reqID})
}

func (h *Handler) handleTopSources(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.TopSources(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sources": out, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		if svcErr.HTTPStatus >= http.StatusInternalServerError {
			_, _ = h.svc.CaptureErrorTelemetry(context.Background(), firstNonEmpty(tenantID, "root"), ErrorTelemetryEvent{
				Source:      "backend",
				Service:     "reporting",
				Component:   "service_error",
				Level:       "error",
				Message:     defaultString(svcErr.Message, "reporting service error"),
				Fingerprint: svcErr.Code,
				RequestID:   reqID,
				ReleaseTag:  h.releaseTag,
				BuildVer:    h.buildVersion,
			})
		}
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	_, _ = h.svc.CaptureErrorTelemetry(context.Background(), firstNonEmpty(tenantID, "root"), ErrorTelemetryEvent{
		Source:      "backend",
		Service:     "reporting",
		Component:   "unhandled_error",
		Level:       "error",
		Message:     err.Error(),
		Fingerprint: "internal_error",
		RequestID:   reqID,
		ReleaseTag:  h.releaseTag,
		BuildVer:    h.buildVersion,
	})
	writeErr(w, httpStatusForErr(err), "internal_error", err.Error(), reqID, tenantID)
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	return firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}

func writeSSE(w http.ResponseWriter, event string, payload interface{}) {
	raw, _ := json.Marshal(payload)
	_, _ = w.Write([]byte("event: " + event + "\n"))
	_, _ = w.Write([]byte("data: " + string(raw) + "\n\n"))
}

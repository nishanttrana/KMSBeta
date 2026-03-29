package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /posture/health", h.handleHealth)
	mux.HandleFunc("POST /posture/events", h.handleIngestEvent)
	mux.HandleFunc("POST /posture/events/batch", h.handleIngestEventsBatch)
	mux.HandleFunc("POST /posture/ingest/audit", h.handleIngestFromAudit)
	mux.HandleFunc("POST /posture/scan", h.handleRunScan)

	mux.HandleFunc("GET /posture/findings", h.handleListFindings)
	mux.HandleFunc("PUT /posture/findings/{id}/status", h.handleUpdateFindingStatus)

	mux.HandleFunc("GET /posture/risk", h.handleLatestRisk)
	mux.HandleFunc("GET /posture/risk/history", h.handleRiskHistory)

	mux.HandleFunc("GET /posture/actions", h.handleListActions)
	mux.HandleFunc("POST /posture/actions/{id}/execute", h.handleExecuteAction)

	mux.HandleFunc("GET /posture/dashboard", h.handleDashboard)

	// Leak scanner routes
	mux.HandleFunc("GET /leaks/targets", h.handleListLeakTargets)
	mux.HandleFunc("POST /leaks/targets", h.handleCreateLeakTarget)
	mux.HandleFunc("DELETE /leaks/targets/{id}", h.handleDeleteLeakTarget)
	mux.HandleFunc("POST /leaks/targets/{id}/scan", h.handleTriggerScan)
	mux.HandleFunc("GET /leaks/jobs", h.handleListLeakJobs)
	mux.HandleFunc("GET /leaks/findings", h.handleListLeakFindings)
	mux.HandleFunc("PATCH /leaks/findings/{id}", h.handleUpdateLeakFinding)

	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"service": "posture",
	})
}

func (h *Handler) handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var payload NormalizedEvent
	if err := decodeJSON(r, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantFromRequest(r))
		return
	}
	if strings.TrimSpace(payload.TenantID) == "" {
		payload.TenantID = tenantFromRequest(r)
	}
	inserted, err := h.svc.IngestEvents(r.Context(), []NormalizedEvent{payload})
	if err != nil {
		h.writeServiceError(w, err, reqID, payload.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inserted":   inserted,
		"request_id": reqID,
	})
}

func (h *Handler) handleIngestEventsBatch(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var payload struct {
		Items []NormalizedEvent `json:"items"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantFromRequest(r))
		return
	}
	tenantID := strings.TrimSpace(tenantFromRequest(r))
	for i := range payload.Items {
		if strings.TrimSpace(payload.Items[i].TenantID) == "" {
			payload.Items[i].TenantID = tenantID
		}
	}
	inserted, err := h.svc.IngestEvents(r.Context(), payload.Items)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inserted":   inserted,
		"request_id": reqID,
	})
}

func (h *Handler) handleIngestFromAudit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"), 500, 1, 5000)
	inserted, err := h.svc.SyncFromAudit(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"inserted":   inserted,
		"tenant_id":  tenantID,
		"request_id": reqID,
	})
}

func (h *Handler) handleRunScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(tenantFromRequest(r))
	syncAudit := parseBool(r.URL.Query().Get("sync_audit"))
	if tenantID == "" || tenantID == "*" || strings.EqualFold(tenantID, "all") {
		if err := h.svc.RunScanAllTenants(r.Context(), syncAudit); err != nil {
			h.writeServiceError(w, err, reqID, tenantID)
			return
		}
		latest, err := h.svc.LatestRisk(r.Context(), "*")
		if err != nil {
			latest = RiskSnapshot{TenantID: "*"}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"risk":       latest,
			"tenant_id":  "*",
			"request_id": reqID,
		})
		return
	}
	snap, err := h.svc.RunScanTenant(r.Context(), tenantID, syncAudit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"risk":       snap,
		"tenant_id":  tenantID,
		"request_id": reqID,
	})
}

func (h *Handler) handleListFindings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	q := FindingQuery{
		Engine:      strings.TrimSpace(r.URL.Query().Get("engine")),
		Status:      strings.TrimSpace(r.URL.Query().Get("status")),
		Severity:    strings.TrimSpace(r.URL.Query().Get("severity")),
		FindingType: strings.TrimSpace(r.URL.Query().Get("finding_type")),
		Limit:       atoi(r.URL.Query().Get("limit"), 200, 1, 1000),
		Offset:      atoi(r.URL.Query().Get("offset"), 0, 0, 100000),
		From:        parseTimeString(r.URL.Query().Get("from")),
		To:          parseTimeString(r.URL.Query().Get("to")),
	}
	items, err := h.svc.ListFindings(r.Context(), tenantID, q)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleUpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateFindingStatus(r.Context(), tenantID, r.PathValue("id"), payload.Status); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"request_id": reqID,
	})
}

func (h *Handler) handleLatestRisk(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(tenantFromRequest(r))
	if tenantID == "" {
		tenantID = "*"
	}
	item, err := h.svc.LatestRisk(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"risk":       RiskSnapshot{TenantID: tenantID},
				"request_id": reqID,
			})
			return
		}
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"risk":       item,
		"request_id": reqID,
	})
}

func (h *Handler) handleRiskHistory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(tenantFromRequest(r))
	if tenantID == "" {
		tenantID = "*"
	}
	q := RiskQuery{
		Limit:  atoi(r.URL.Query().Get("limit"), 200, 1, 1000),
		Offset: atoi(r.URL.Query().Get("offset"), 0, 0, 100000),
	}
	items, err := h.svc.RiskHistory(r.Context(), tenantID, q)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleListActions(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	q := ActionQuery{
		Status:     strings.TrimSpace(r.URL.Query().Get("status")),
		ActionType: strings.TrimSpace(r.URL.Query().Get("action_type")),
		Limit:      atoi(r.URL.Query().Get("limit"), 200, 1, 1000),
		Offset:     atoi(r.URL.Query().Get("offset"), 0, 0, 100000),
	}
	items, err := h.svc.ListActions(r.Context(), tenantID, q)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleExecuteAction(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var payload struct {
		Actor             string `json:"actor"`
		ApprovalRequestID string `json:"approval_request_id"`
	}
	if r.Body != nil {
		_ = decodeJSON(r, &payload)
	}
	actor := firstNonEmpty(payload.Actor, r.Header.Get("X-Actor-ID"), "system")
	if err := h.svc.ExecuteAction(r.Context(), tenantID, r.PathValue("id"), actor, payload.ApprovalRequestID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"request_id": reqID,
	})
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(tenantFromRequest(r))
	if tenantID == "" {
		tenantID = "*"
	}
	out, err := h.svc.Dashboard(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"risk":                out.Risk,
		"recent_findings":     out.RecentFindings,
		"pending_actions":     out.PendingActions,
		"open_findings":       out.OpenFindings,
		"critical_findings":   out.CriticalFindings,
		"risk_drivers":        out.RiskDrivers,
		"remediation_cockpit": out.RemediationCockpit,
		"blast_radius":        out.BlastRadius,
		"scenario_simulator":  out.ScenarioSimulator,
		"validation_badges":   out.ValidationBadges,
		"sla_overview":        out.SLAOverview,
		"request_id":          reqID,
	})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	writeErr(w, http.StatusInternalServerError, "internal_error", err.Error(), reqID, tenantID)
}

func atoi(raw string, fallback int, min int, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if n < min {
		n = min
	}
	if max > 0 && n > max {
		n = max
	}
	return n
}

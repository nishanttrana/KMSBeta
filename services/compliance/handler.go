package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	mux.HandleFunc("GET /compliance/posture", h.handlePosture)
	mux.HandleFunc("GET /compliance/posture/history", h.handlePostureHistory)
	mux.HandleFunc("GET /compliance/posture/breakdown", h.handlePostureBreakdown)
	mux.HandleFunc("GET /compliance/assessment", h.handleAssessment)
	mux.HandleFunc("POST /compliance/assessment/run", h.handleRunAssessment)
	mux.HandleFunc("GET /compliance/assessment/history", h.handleAssessmentHistory)
	mux.HandleFunc("GET /compliance/assessment/schedule", h.handleAssessmentSchedule)
	mux.HandleFunc("PUT /compliance/assessment/schedule", h.handleUpsertAssessmentSchedule)
	mux.HandleFunc("GET /compliance/templates", h.handleListComplianceTemplates)
	mux.HandleFunc("POST /compliance/templates", h.handleUpsertComplianceTemplate)
	mux.HandleFunc("GET /compliance/templates/{id}", h.handleGetComplianceTemplate)
	mux.HandleFunc("DELETE /compliance/templates/{id}", h.handleDeleteComplianceTemplate)

	mux.HandleFunc("GET /compliance/frameworks", h.handleFrameworks)
	mux.HandleFunc("GET /compliance/frameworks/{id}/controls", h.handleFrameworkControls)
	mux.HandleFunc("GET /compliance/frameworks/{id}/gaps", h.handleFrameworkGaps)

	mux.HandleFunc("GET /compliance/keys/hygiene", h.handleKeyHygiene)
	mux.HandleFunc("GET /compliance/keys/orphaned", h.handleOrphaned)
	mux.HandleFunc("GET /compliance/keys/expired", h.handleExpired)

	mux.HandleFunc("GET /compliance/audit/correlations", h.handleAuditCorrelations)
	mux.HandleFunc("GET /compliance/audit/anomalies", h.handleAuditAnomalies)

	mux.HandleFunc("GET /compliance/sbom", h.handleSBOM)
	mux.HandleFunc("GET /compliance/sbom/services", h.handleSBOMServices)
	mux.HandleFunc("GET /compliance/sbom/services/{name}", h.handleSBOMService)
	mux.HandleFunc("GET /compliance/sbom/vulnerabilities", h.handleSBOMVulnerabilities)

	mux.HandleFunc("GET /compliance/cbom", h.handleCBOM)
	mux.HandleFunc("GET /compliance/cbom/summary", h.handleCBOMSummary)
	mux.HandleFunc("GET /compliance/cbom/export", h.handleCBOMExport)
	mux.HandleFunc("GET /compliance/cbom/pqc-readiness", h.handleCBOMPQCReadiness)
	mux.HandleFunc("GET /compliance/cbom/diff", h.handleCBOMDiff)
	return mux
}

func (h *Handler) handlePosture(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	refresh := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("refresh")), "true")
	item, err := h.svc.GetPosture(r.Context(), tenantID, refresh)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"posture": item, "request_id": reqID})
}

func (h *Handler) handlePostureHistory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	items, err := h.svc.GetPostureHistory(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handlePostureBreakdown(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetPostureBreakdown(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"breakdown": out, "request_id": reqID})
}

func (h *Handler) handleAssessment(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	templateID := strings.TrimSpace(r.URL.Query().Get("template_id"))
	item, err := h.svc.GetLatestAssessment(r.Context(), tenantID, templateID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"assessment": item, "request_id": reqID})
}

func (h *Handler) handleRunAssessment(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body struct {
		TemplateID string `json:"template_id"`
		Recompute  *bool  `json:"recompute"`
	}
	templateID := strings.TrimSpace(r.URL.Query().Get("template_id"))
	recompute := true
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		templateID = firstNonEmpty(templateID, body.TemplateID)
		if body.Recompute != nil {
			recompute = *body.Recompute
		}
	}
	item, err := h.svc.RunAssessment(r.Context(), tenantID, "manual", recompute, templateID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"assessment": item, "request_id": reqID})
}

func (h *Handler) handleAssessmentHistory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	templateID := strings.TrimSpace(r.URL.Query().Get("template_id"))
	items, err := h.svc.ListAssessmentRuns(r.Context(), tenantID, templateID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleListComplianceTemplates(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListComplianceTemplates(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetComplianceTemplate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetComplianceTemplate(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"template": item, "request_id": reqID})
}

func (h *Handler) handleUpsertComplianceTemplate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body ComplianceTemplate
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, strings.TrimSpace(r.Header.Get("X-Tenant-ID")), strings.TrimSpace(r.URL.Query().Get("tenant_id")))
	if body.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	item, err := h.svc.UpsertComplianceTemplate(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"template": item, "request_id": reqID})
}

func (h *Handler) handleDeleteComplianceTemplate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteComplianceTemplate(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleAssessmentSchedule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetAssessmentSchedule(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"schedule": item, "request_id": reqID})
}

func (h *Handler) handleUpsertAssessmentSchedule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID  string `json:"tenant_id"`
		Enabled   bool   `json:"enabled"`
		Frequency string `json:"frequency"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
	if strings.TrimSpace(body.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	item, err := h.svc.UpsertAssessmentSchedule(r.Context(), AssessmentSchedule{
		TenantID:  body.TenantID,
		Enabled:   body.Enabled,
		Frequency: body.Frequency,
	})
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"schedule": item, "request_id": reqID})
}

func (h *Handler) handleFrameworks(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": h.svc.ListFrameworks(), "request_id": reqID})
}

func (h *Handler) handleFrameworkControls(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	controls, assess, err := h.svc.GetFrameworkControls(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"framework_id": normalizeFrameworkID(r.PathValue("id")),
		"score":        assess.Score,
		"status":       assess.Status,
		"controls":     controls,
		"request_id":   reqID,
	})
}

func (h *Handler) handleFrameworkGaps(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	gaps, err := h.svc.GetFrameworkGaps(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": gaps, "request_id": reqID})
}

func (h *Handler) handleKeyHygiene(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetKeyHygieneReport(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"report": out, "request_id": reqID})
}

func (h *Handler) handleOrphaned(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.GetOrphanedKeys(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleExpired(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.GetExpiredKeys(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleAuditCorrelations(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	items, err := h.svc.GetAuditCorrelations(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleAuditAnomalies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.GetAuditAnomalies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSBOM(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	format := firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("format")), "cyclonedx")
	doc, err := h.svc.GenerateSBOM(r.Context(), format)
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sbom": doc, "request_id": reqID})
}

func (h *Handler) handleSBOMServices(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	items, err := h.svc.SBOMServices(r.Context())
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSBOMService(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	item, err := h.svc.SBOMService(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleSBOMVulnerabilities(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.SBOMVulnerabilities(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCBOM(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	doc, err := h.svc.GenerateCBOM(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"cbom": doc, "request_id": reqID})
}

func (h *Handler) handleCBOMSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.CBOMSummary(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": out, "request_id": reqID})
}

func (h *Handler) handleCBOMExport(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	doc, err := h.svc.GenerateCBOM(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"format":     format,
		"export":     doc,
		"request_id": reqID,
	})
}

func (h *Handler) handleCBOMPQCReadiness(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.CBOMPQCReadiness(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pqc_readiness": out, "request_id": reqID})
}

func (h *Handler) handleCBOMDiff(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	from := parseDateParam(strings.TrimSpace(r.URL.Query().Get("from")))
	to := parseDateParam(strings.TrimSpace(r.URL.Query().Get("to")))
	out, err := h.svc.CBOMDiff(r.Context(), tenantID, from, to)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"diff": out, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
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

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := firstNonEmpty(
		strings.TrimSpace(r.URL.Query().Get("tenant_id")),
		strings.TrimSpace(r.Header.Get("X-Tenant-ID")),
	)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
